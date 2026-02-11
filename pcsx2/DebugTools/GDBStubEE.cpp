// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "DebugTools/GDBStubEE.h"

#include "DebugTools/Breakpoints.h"
#include "DebugTools/DebugInterface.h"
#include "DebugTools/MIPSAnalyst.h"
#include "Host.h"
#include "MemoryTypes.h"
#include "R5900.h"
#include "VMManager.h"
#include "common/Assertions.h"
#include "common/Console.h"
#include "common/Threading.h"
#include "fmt/format.h"
#include "vtlb.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef ENABLE_EE_GDBSTUB
#include "gdbstub/gdbstub.hpp"
#endif

namespace EEGDBStub
{
#ifdef ENABLE_EE_GDBSTUB

namespace
{
	static constexpr int EE_GPR_COUNT = 32;
	static constexpr int EE_PC_REG = 32;
	static constexpr int EE_HI_REG = 33;
	static constexpr int EE_LO_REG = 34;
	static constexpr int EE_REG_COUNT = 35;
	static constexpr int EE_SIGNAL_TRAP = 5;
	static constexpr int EE_SIGNAL_INTERRUPT = 2;
	static constexpr char OSD_KEY[] = "EEGDBStub";
	static constexpr u64 EE_THREAD_ID = 1;
	static constexpr int EE_PROCESS_ID = 1;
	static constexpr int EE_TARGET_PTR_SIZE = 4;
	static constexpr int EE_TARGET_ADDRESS_BITS = 32;
	static constexpr char EE_TARGET_TRIPLE[] = "mips64el-unknown-none-elf";
	static constexpr char EE_TARGET_ENDIAN[] = "little";
	static constexpr char EE_TARGET_HOSTNAME[] = "pcsx2-ee";
	static constexpr char EE_TARGET_OSTYPE[] = "none";
	static constexpr char EE_THREAD_NAME[] = "EE";

	static constexpr std::array<const char*, EE_GPR_COUNT> EE_GPR_NAMES = {
		"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
		"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
		"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
		"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
	};

	enum class ServiceState : u8
	{
		Disabled = 0,
		Starting,
		Listening,
		Connected,
		Faulted,
		Stopping,
	};

	struct RemoteBreakpointEntry
	{
		u32 refcount = 0;
		bool remote_created = false;
	};

	struct WatchpointKey
	{
		gdbstub::breakpoint_type type = gdbstub::breakpoint_type::watch_access;
		u32 start = 0;
		u32 end = 0;

		bool operator==(const WatchpointKey& rhs) const
		{
			return type == rhs.type && start == rhs.start && end == rhs.end;
		}
	};

	struct WatchpointKeyHash
	{
		size_t operator()(const WatchpointKey& key) const noexcept
		{
			const size_t a = static_cast<size_t>(static_cast<u8>(key.type));
			const size_t b = static_cast<size_t>(key.start);
			const size_t c = static_cast<size_t>(key.end);
			return (a * 1315423911ull) ^ (b * 2654435761ull) ^ (c * 2246822519ull);
		}
	};

	struct RemoteWatchpointEntry
	{
		u32 refcount = 0;
		bool remote_created = false;
	};

	static const char* ServiceStateName(ServiceState state)
	{
		switch (state)
		{
			case ServiceState::Disabled:
				return "Disabled";
			case ServiceState::Starting:
				return "Starting";
			case ServiceState::Listening:
				return "Listening";
			case ServiceState::Connected:
				return "Connected";
			case ServiceState::Faulted:
				return "Faulted";
			case ServiceState::Stopping:
				return "Stopping";
			default:
				return "Unknown";
		}
	}

	static bool IsEEAddressRangeValid(u64 addr, size_t size)
	{
		if (addr > std::numeric_limits<u32>::max())
			return false;

		const u64 end = addr + static_cast<u64>(size);
		return (end <= (static_cast<u64>(std::numeric_limits<u32>::max()) + 1ull));
	}

	static u32 NormalizeEEBreakpointAddress(u64 addr)
	{
		return standardizeBreakpointAddress(static_cast<u32>(addr));
	}

	static u64 DecodeU64LE(std::span<const std::byte> data)
	{
		u64 value = 0;
		for (size_t i = 0; i < data.size() && i < sizeof(u64); i++)
			value |= (static_cast<u64>(std::to_integer<u8>(data[i])) << (i * 8));
		return value;
	}

	static void EncodeU64LE(u64 value, std::span<std::byte> out)
	{
		for (size_t i = 0; i < out.size() && i < sizeof(u64); i++)
			out[i] = std::byte((value >> (i * 8)) & 0xFF);
	}

	template <typename Fn>
	static void RunOnCPUThreadBlocking(Fn&& fn)
	{
		Host::RunOnCPUThread(std::forward<Fn>(fn), true);
	}

	template <typename Fn>
	static auto RunOnCPUThreadBlockingResult(Fn&& fn)
	{
		using Result = std::invoke_result_t<Fn>;
		static_assert(!std::is_void_v<Result>);
		std::optional<Result> result;
		Host::RunOnCPUThread([&result, f = std::forward<Fn>(fn)]() mutable { result = f(); }, true);
		pxAssertRel(result.has_value(), "CPU thread dispatch did not provide a result.");
		return std::move(*result);
	}

	static gdbstub::target_status MemCondFromBreakpointType(gdbstub::breakpoint_type type, MemCheckCondition* out_cond)
	{
		switch (type)
		{
			case gdbstub::breakpoint_type::watch_read:
				*out_cond = MEMCHECK_READ;
				return gdbstub::target_status::ok;
			case gdbstub::breakpoint_type::watch_write:
				*out_cond = MEMCHECK_WRITE;
				return gdbstub::target_status::ok;
			case gdbstub::breakpoint_type::watch_access:
				*out_cond = MEMCHECK_READWRITE;
				return gdbstub::target_status::ok;
			default:
				return gdbstub::target_status::unsupported;
		}
	}

	static std::string BuildTargetXML()
	{
		std::string xml;
		xml.reserve(2048);
		xml += R"(<?xml version="1.0"?><target version="1.0"><architecture>mips64el</architecture><feature name="org.gnu.gdb.mips.cpu">)";
		for (int i = 0; i < EE_GPR_COUNT; i++)
		{
			xml += fmt::format(R"(<reg name="{}" bitsize="64" regnum="{}"{}/>)",
				EE_GPR_NAMES[static_cast<size_t>(i)], i, (i == 29 ? R"( generic="sp")" : ""));
		}
		xml += fmt::format(R"(<reg name="pc" bitsize="64" regnum="{}" generic="pc"/>)", EE_PC_REG);
		xml += fmt::format(R"(<reg name="hi" bitsize="64" regnum="{}"/>)", EE_HI_REG);
		xml += fmt::format(R"(<reg name="lo" bitsize="64" regnum="{}"/>)", EE_LO_REG);
		xml += "</feature></target>";
		return xml;
	}

	class EEGDBStubService;

	class EERegsCapability
	{
	public:
		explicit EERegsCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		size_t reg_size(int regno);
		gdbstub::target_status read_reg(int regno, std::span<std::byte> out);
		gdbstub::target_status write_reg(int regno, std::span<const std::byte> data);

	private:
		EEGDBStubService& m_service;
	};

	class EEMemoryCapability
	{
	public:
		explicit EEMemoryCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		gdbstub::target_status read_mem(u64 addr, std::span<std::byte> out);
		gdbstub::target_status write_mem(u64 addr, std::span<const std::byte> data);

	private:
		EEGDBStubService& m_service;
	};

	class EERunCapability
	{
	public:
		explicit EERunCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		gdbstub::resume_result resume(const gdbstub::resume_request& request);
		void interrupt();
		std::optional<gdbstub::stop_reason> poll_stop();

	private:
		EEGDBStubService& m_service;
	};

	class EEBreakpointCapability
	{
	public:
		explicit EEBreakpointCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		gdbstub::target_status set_breakpoint(const gdbstub::breakpoint_request& request);
		gdbstub::target_status remove_breakpoint(const gdbstub::breakpoint_request& request);
		gdbstub::breakpoint_capabilities capabilities();

	private:
		EEGDBStubService& m_service;
	};

	class EERegisterInfoCapability
	{
	public:
		explicit EERegisterInfoCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		std::optional<gdbstub::register_info> get_register_info(int regno);

	private:
		EEGDBStubService& m_service;
	};

	class EEThreadsCapability
	{
	public:
		explicit EEThreadsCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		std::vector<u64> thread_ids();
		u64 current_thread();
		gdbstub::target_status set_current_thread(u64 tid);
		std::optional<u64> thread_pc(u64 tid);
		std::optional<std::string> thread_name(u64 tid);
		std::optional<gdbstub::stop_reason> thread_stop_reason(u64 tid);

	private:
		EEGDBStubService& m_service;
	};

	class EEIdentityCapability
	{
	public:
		explicit EEIdentityCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		std::optional<gdbstub::host_info> get_host_info();
		std::optional<gdbstub::process_info> get_process_info();

	private:
		EEGDBStubService& m_service;
	};

	class EEMemoryLayoutCapability
	{
	public:
		explicit EEMemoryLayoutCapability(EEGDBStubService& service)
			: m_service(service)
		{
		}

		std::vector<gdbstub::memory_region> memory_map();

	private:
		EEGDBStubService& m_service;
	};

	class EEGDBStubService
	{
	public:
		bool Initialize(const Config& config);
		void Deinitialize();
		bool IsInitialized() const;
		u16 GetPort() const;
		bool GetPauseOnConnect() const;

		size_t RegSize(int regno);
		gdbstub::target_status ReadReg(int regno, std::span<std::byte> out);
		gdbstub::target_status WriteReg(int regno, std::span<const std::byte> data);
		gdbstub::target_status ReadMem(u64 addr, std::span<std::byte> out);
		gdbstub::target_status WriteMem(u64 addr, std::span<const std::byte> data);
		gdbstub::resume_result Resume(const gdbstub::resume_request& request);
		void Interrupt();
		std::optional<gdbstub::stop_reason> PollStop();
		gdbstub::target_status SetBreakpoint(const gdbstub::breakpoint_request& request);
		gdbstub::target_status RemoveBreakpoint(const gdbstub::breakpoint_request& request);
		gdbstub::breakpoint_capabilities GetBreakpointCapabilities() const;
		std::optional<gdbstub::register_info> GetRegisterInfo(int regno);
		std::vector<u64> GetThreadIds() const;
		u64 GetCurrentThread() const;
		gdbstub::target_status SetCurrentThread(u64 tid);
		std::optional<u64> GetThreadPC(u64 tid);
		std::optional<std::string> GetThreadName(u64 tid) const;
		std::optional<gdbstub::stop_reason> GetThreadStopReason(u64 tid) const;
		std::optional<gdbstub::host_info> GetHostInfo() const;
		std::optional<gdbstub::process_info> GetProcessInfo() const;
		std::vector<gdbstub::memory_region> GetMemoryMap() const;

	private:
		void ThreadMain();
		void SetState(ServiceState state);
		bool ShouldStop() const;
		void CleanupRemoteOwnedBreakpointsAndWatchpoints();
		void CleanupRemoteStepBreakpointOnStop();
		u32 ComputeSingleStepBreakpoint();
		void HandleDebuggerConnected();
		gdbstub::stop_reason BuildStopReasonForPausedState();
		std::optional<WatchpointKey> MakeWatchpointKey(const gdbstub::breakpoint_request& request) const;

	private:
		mutable std::mutex m_mutex;
		Config m_config = {};
		ServiceState m_state = ServiceState::Disabled;
		bool m_initialized = false;
		std::atomic<bool> m_stop_requested{false};
		std::thread m_thread;

		std::unique_ptr<EERegsCapability> m_regs;
		std::unique_ptr<EEMemoryCapability> m_mem;
		std::unique_ptr<EERunCapability> m_run;
		std::unique_ptr<EEBreakpointCapability> m_breakpoints;
		std::unique_ptr<EERegisterInfoCapability> m_reg_info;
		std::unique_ptr<EEThreadsCapability> m_threads;
		std::unique_ptr<EEIdentityCapability> m_identity;
		std::unique_ptr<EEMemoryLayoutCapability> m_memory_layout;
		std::unique_ptr<gdbstub::server> m_server;

		// Accessed only on the gdbstub worker thread; deinitialize touches after worker join.
		std::unordered_map<u32, RemoteBreakpointEntry> m_remote_breakpoints;
		std::unordered_map<WatchpointKey, RemoteWatchpointEntry, WatchpointKeyHash> m_remote_watchpoints;
		std::optional<u32> m_remote_step_temp_bp;
		bool m_waiting_for_stop = false;
		bool m_last_resume_was_step = false;
		std::optional<gdbstub::stop_reason> m_last_stop_reason;
	};

	bool EEGDBStubService::ShouldStop() const
	{
		return m_stop_requested.load(std::memory_order_acquire);
	}

	void EEGDBStubService::SetState(ServiceState state)
	{
		std::lock_guard lock(m_mutex);
		if (m_state == state)
			return;

		Console.WriteLn("EEGDBStub: state %s -> %s", ServiceStateName(m_state), ServiceStateName(state));
		m_state = state;
	}

	bool EEGDBStubService::Initialize(const Config& config)
	{
		Deinitialize();

		if (!Host::HasCPUThreadDispatcher())
		{
			Console.Warning("EEGDBStub: Host does not support CPU-thread dispatch, disabling service.");
			return false;
		}

		if (config.port == 0)
		{
			Console.Warning("EEGDBStub: Invalid port 0, disabling service.");
			return false;
		}

		SetState(ServiceState::Starting);

		auto regs = std::make_unique<EERegsCapability>(*this);
		auto mem = std::make_unique<EEMemoryCapability>(*this);
		auto run = std::make_unique<EERunCapability>(*this);
		auto breakpoints = std::make_unique<EEBreakpointCapability>(*this);
		auto reg_info = std::make_unique<EERegisterInfoCapability>(*this);
		auto threads = std::make_unique<EEThreadsCapability>(*this);
		auto identity = std::make_unique<EEIdentityCapability>(*this);
		auto memory_layout = std::make_unique<EEMemoryLayoutCapability>(*this);

		gdbstub::target target = gdbstub::make_target(
			*regs, *mem, *run, *breakpoints, *reg_info, *threads, *identity, *memory_layout);

		gdbstub::arch_spec arch;
		arch.target_xml = BuildTargetXML();
		arch.xml_arch_name = "mips64el";
		arch.osabi = "none";
		arch.reg_count = EE_REG_COUNT;
		arch.pc_reg_num = EE_PC_REG;
		arch.address_bits = EE_TARGET_ADDRESS_BITS;
		arch.swap_register_endianness = false;

		auto transport = std::make_unique<gdbstub::transport_tcp>();
		auto server = std::make_unique<gdbstub::server>(std::move(target), std::move(arch), std::move(transport));

		const std::string bind_addr = fmt::format("127.0.0.1:{}", config.port);
		if (!server->listen(bind_addr))
		{
			Console.Error("EEGDBStub: Failed to listen on %s", bind_addr.c_str());
			Host::AddKeyedOSDMessage(OSD_KEY,
				fmt::format(TRANSLATE_FS("EEGDBStub", "Failed to initialize EE gdbstub on {}."), bind_addr),
				Host::OSD_ERROR_DURATION);
			SetState(ServiceState::Faulted);
			return false;
		}

		{
			std::lock_guard lock(m_mutex);
			m_config = config;
			m_regs = std::move(regs);
			m_mem = std::move(mem);
			m_run = std::move(run);
			m_breakpoints = std::move(breakpoints);
			m_reg_info = std::move(reg_info);
			m_threads = std::move(threads);
			m_identity = std::move(identity);
			m_memory_layout = std::move(memory_layout);
			m_server = std::move(server);
			m_remote_breakpoints.clear();
			m_remote_watchpoints.clear();
			m_remote_step_temp_bp.reset();
			m_waiting_for_stop = false;
			m_last_resume_was_step = false;
			m_last_stop_reason.reset();
			m_stop_requested.store(false, std::memory_order_release);
			m_initialized = true;
		}

		Console.WriteLn("EEGDBStub: Listening on %s (pause_on_connect=%s)",
			bind_addr.c_str(), config.pause_on_connect ? "true" : "false");

		m_thread = std::thread(&EEGDBStubService::ThreadMain, this);
		return true;
	}

	void EEGDBStubService::ThreadMain()
	{
		Threading::SetNameOfCurrentThread("EE GDBStub");

		gdbstub::server* server = nullptr;
		{
			std::lock_guard lock(m_mutex);
			server = m_server.get();
		}

		if (!server)
		{
			SetState(ServiceState::Faulted);
			return;
		}

		SetState(ServiceState::Listening);

		while (!ShouldStop())
		{
			if (!server->wait_for_connection())
			{
				if (ShouldStop())
					break;
				continue;
			}

			SetState(ServiceState::Connected);
			HandleDebuggerConnected();

			while (!ShouldStop() && server->has_connection())
				server->poll(std::chrono::milliseconds(100));

			if (!ShouldStop())
			{
				CleanupRemoteOwnedBreakpointsAndWatchpoints();
				SetState(ServiceState::Listening);
			}
		}
	}

	void EEGDBStubService::Deinitialize()
	{
		bool was_initialized = false;
		{
			std::lock_guard lock(m_mutex);
			was_initialized = m_initialized;
		}
		if (!was_initialized)
			return;

		SetState(ServiceState::Stopping);

		std::thread thread_to_join;
		{
			std::lock_guard lock(m_mutex);
			m_stop_requested.store(true, std::memory_order_release);
			if (m_server)
				m_server->stop();

			thread_to_join = std::move(m_thread);
			m_initialized = false;
		}

		if (thread_to_join.joinable())
			thread_to_join.join();

		CleanupRemoteOwnedBreakpointsAndWatchpoints();

		{
			std::lock_guard lock(m_mutex);
			m_server.reset();
			m_memory_layout.reset();
			m_identity.reset();
			m_threads.reset();
			m_reg_info.reset();
			m_breakpoints.reset();
			m_run.reset();
			m_mem.reset();
			m_regs.reset();
			m_remote_breakpoints.clear();
			m_remote_watchpoints.clear();
			m_remote_step_temp_bp.reset();
			m_waiting_for_stop = false;
			m_last_resume_was_step = false;
			m_last_stop_reason.reset();
			m_stop_requested.store(false, std::memory_order_release);
		}

		SetState(ServiceState::Disabled);
		Console.WriteLn("EEGDBStub: Deinitialized");
	}

	bool EEGDBStubService::IsInitialized() const
	{
		std::lock_guard lock(m_mutex);
		return m_initialized;
	}

	u16 EEGDBStubService::GetPort() const
	{
		std::lock_guard lock(m_mutex);
		return m_config.port;
	}

	bool EEGDBStubService::GetPauseOnConnect() const
	{
		std::lock_guard lock(m_mutex);
		return m_config.pause_on_connect;
	}

	void EEGDBStubService::HandleDebuggerConnected()
	{
		bool pause_on_connect = false;
		{
			std::lock_guard lock(m_mutex);
			pause_on_connect = m_config.pause_on_connect;
		}

		if (!pause_on_connect)
			return;

		// Do not block connection handshakes while waiting for a VM-thread pause transition.
		Host::RunOnCPUThread([]() {
			if (VMManager::GetState() != VMState::Running)
				return;

			BreakpointTriggerInfo info;
			info.kind = BreakpointTriggerKind::ManualPause;
			info.cpu = BREAKPOINT_EE;
			info.pc = r5900Debug.getPC();
			info.addr = info.pc;
			info.size = 0;
			CBreakPoints::SetBreakpointTriggerInfo(info);
			VMManager::SetPaused(true);
		});
	}

	void EEGDBStubService::CleanupRemoteOwnedBreakpointsAndWatchpoints()
	{
		std::vector<u32> temp_breakpoints;
		temp_breakpoints.reserve(m_remote_breakpoints.size() + (m_remote_step_temp_bp.has_value() ? 1 : 0));
		for (const auto& [addr, entry] : m_remote_breakpoints)
		{
			if (entry.remote_created)
				temp_breakpoints.push_back(addr);
		}

		if (m_remote_step_temp_bp.has_value())
			temp_breakpoints.push_back(*m_remote_step_temp_bp);

		std::vector<std::pair<u32, u32>> watch_ranges;
		watch_ranges.reserve(m_remote_watchpoints.size());
		for (const auto& [key, entry] : m_remote_watchpoints)
		{
			if (entry.remote_created)
				watch_ranges.emplace_back(key.start, key.end);
		}

		if (!temp_breakpoints.empty() || !watch_ranges.empty())
		{
			RunOnCPUThreadBlocking([breakpoints = std::move(temp_breakpoints), watchpoints = std::move(watch_ranges)]() {
				for (const u32 addr : breakpoints)
					CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, addr, true);

				for (const auto& [start, end] : watchpoints)
					CBreakPoints::RemoveMemCheck(BREAKPOINT_EE, start, end);
			});
		}

		m_remote_breakpoints.clear();
		m_remote_watchpoints.clear();
		m_remote_step_temp_bp.reset();
		m_waiting_for_stop = false;
		m_last_resume_was_step = false;
		m_last_stop_reason.reset();
	}

	size_t EEGDBStubService::RegSize(int regno)
	{
		if (regno < 0 || regno >= EE_REG_COUNT)
			return 0;
		return sizeof(u64);
	}

	gdbstub::target_status EEGDBStubService::ReadReg(int regno, std::span<std::byte> out)
	{
		if (RegSize(regno) == 0 || out.size() != sizeof(u64))
			return gdbstub::target_status::invalid;

		const u64 value = RunOnCPUThreadBlockingResult([regno]() -> u64 {
			if (regno < EE_GPR_COUNT)
				return r5900Debug.getRegister(EECAT_GPR, regno).lo;
			if (regno == EE_PC_REG)
				return static_cast<u64>(r5900Debug.getPC());
			if (regno == EE_HI_REG)
				return r5900Debug.getHI().lo;
			if (regno == EE_LO_REG)
				return r5900Debug.getLO().lo;
			return 0;
		});

		EncodeU64LE(value, out);
		return gdbstub::target_status::ok;
	}

	gdbstub::target_status EEGDBStubService::WriteReg(int regno, std::span<const std::byte> data)
	{
		if (RegSize(regno) == 0 || data.size() != sizeof(u64))
			return gdbstub::target_status::invalid;

		const u64 value = DecodeU64LE(data);

		return RunOnCPUThreadBlockingResult([regno, value]() -> gdbstub::target_status {
			if (regno < EE_GPR_COUNT)
			{
				r5900Debug.setRegister(EECAT_GPR, regno, u128::From64(value));
				return gdbstub::target_status::ok;
			}
			if (regno == EE_PC_REG)
			{
				r5900Debug.setPc(static_cast<u32>(value));
				return gdbstub::target_status::ok;
			}
			if (regno == EE_HI_REG)
			{
				cpuRegs.HI.UD[0] = value;
				return gdbstub::target_status::ok;
			}
			if (regno == EE_LO_REG)
			{
				cpuRegs.LO.UD[0] = value;
				return gdbstub::target_status::ok;
			}
			return gdbstub::target_status::invalid;
		});
	}

	gdbstub::target_status EEGDBStubService::ReadMem(u64 addr, std::span<std::byte> out)
	{
		if (!IsEEAddressRangeValid(addr, out.size()))
			return gdbstub::target_status::fault;

		const bool ok = RunOnCPUThreadBlockingResult([addr, &out]() {
			return vtlb_memSafeReadBytes(static_cast<u32>(addr), out.data(), static_cast<u32>(out.size()));
		});
		return ok ? gdbstub::target_status::ok : gdbstub::target_status::fault;
	}

	gdbstub::target_status EEGDBStubService::WriteMem(u64 addr, std::span<const std::byte> data)
	{
		if (!IsEEAddressRangeValid(addr, data.size()))
			return gdbstub::target_status::fault;

		const bool ok = RunOnCPUThreadBlockingResult([addr, &data]() {
			return vtlb_memSafeWriteBytes(static_cast<u32>(addr), data.data(), static_cast<u32>(data.size()));
		});
		return ok ? gdbstub::target_status::ok : gdbstub::target_status::fault;
	}

	u32 EEGDBStubService::ComputeSingleStepBreakpoint()
	{
		const u32 pc = r5900Debug.getPC();
		const MIPSAnalyst::MipsOpcodeInfo info = MIPSAnalyst::GetOpcodeInfo(&r5900Debug, pc);

		u32 bp_addr = pc + 4;
		if (info.isBranch)
		{
			if (!info.isConditional)
			{
				bp_addr = info.branchTarget;
			}
			else
			{
				bp_addr = info.conditionMet ? info.branchTarget : (pc + (2 * 4));
			}
		}
		if (info.isSyscall)
			bp_addr = info.branchTarget;
		return bp_addr;
	}

	gdbstub::resume_result EEGDBStubService::Resume(const gdbstub::resume_request& request)
	{
		gdbstub::resume_result result;
		result.state = gdbstub::resume_result::state::running;
		result.status = gdbstub::target_status::ok;

		if (request.direction == gdbstub::resume_direction::reverse)
		{
			result.state = gdbstub::resume_result::state::stopped;
			result.status = gdbstub::target_status::unsupported;
			return result;
		}

		if (request.action == gdbstub::resume_action::range_step)
		{
			result.state = gdbstub::resume_result::state::stopped;
			result.status = gdbstub::target_status::unsupported;
			return result;
		}

		const bool ok = RunOnCPUThreadBlockingResult([this, &request]() {
			if (!VMManager::HasValidVM())
				return false;

			if (request.addr.has_value())
				r5900Debug.setPc(static_cast<u32>(*request.addr));

			if (request.action == gdbstub::resume_action::step)
			{
				if (m_remote_step_temp_bp.has_value())
				{
					CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, *m_remote_step_temp_bp, true);
					m_remote_step_temp_bp.reset();
				}

				const u32 current_pc = r5900Debug.getPC();
				const u32 bp_addr = ComputeSingleStepBreakpoint();
				CBreakPoints::SetSkipFirst(BREAKPOINT_EE, current_pc);

				if (!CBreakPoints::IsAddressBreakPoint(BREAKPOINT_EE, bp_addr))
				{
					const bool temp_exists = CBreakPoints::IsTempBreakPoint(BREAKPOINT_EE, bp_addr);
					if (!temp_exists)
					{
						CBreakPoints::AddBreakPoint(BREAKPOINT_EE, bp_addr, true, true, true);
						m_remote_step_temp_bp = bp_addr;
					}
				}
			}

			VMManager::SetPaused(false);
			return true;
		});

		if (!ok)
		{
			result.state = gdbstub::resume_result::state::stopped;
			result.status = gdbstub::target_status::fault;
			return result;
		}

		m_waiting_for_stop = true;
		m_last_resume_was_step = (request.action == gdbstub::resume_action::step);
		return result;
	}

	void EEGDBStubService::Interrupt()
	{
		RunOnCPUThreadBlocking([]() {
			if (!VMManager::HasValidVM())
				return;

			BreakpointTriggerInfo info;
			info.kind = BreakpointTriggerKind::ManualPause;
			info.cpu = BREAKPOINT_EE;
			info.pc = r5900Debug.getPC();
			info.addr = info.pc;
			info.size = 0;
			CBreakPoints::SetBreakpointTriggerInfo(info);
			VMManager::SetPaused(true);
		});
	}

	void EEGDBStubService::CleanupRemoteStepBreakpointOnStop()
	{
		if (!m_remote_step_temp_bp.has_value())
			return;

		CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, *m_remote_step_temp_bp, true);
		m_remote_step_temp_bp.reset();
	}

	gdbstub::stop_reason EEGDBStubService::BuildStopReasonForPausedState()
	{
		std::optional<BreakpointTriggerInfo> trigger = CBreakPoints::ConsumeBreakpointTriggerInfo();
		if (!trigger.has_value() && CBreakPoints::GetBreakpointTriggered() &&
			CBreakPoints::GetBreakpointTriggeredCpu() == BREAKPOINT_EE)
		{
			BreakpointTriggerInfo fallback;
			fallback.kind = BreakpointTriggerKind::AddressBreakpoint;
			fallback.cpu = BREAKPOINT_EE;
			fallback.pc = r5900Debug.getPC();
			fallback.addr = fallback.pc;
			fallback.size = 4;
			trigger = fallback;
		}

		CBreakPoints::SetBreakpointTriggered(false, BREAKPOINT_IOP_AND_EE);
		CleanupRemoteStepBreakpointOnStop();

		if (!trigger.has_value() && m_last_resume_was_step)
		{
			BreakpointTriggerInfo step_info;
			step_info.kind = BreakpointTriggerKind::StepComplete;
			step_info.cpu = BREAKPOINT_EE;
			step_info.pc = r5900Debug.getPC();
			step_info.addr = step_info.pc;
			step_info.size = 4;
			trigger = step_info;
		}

		gdbstub::stop_reason reason;
		reason.kind = gdbstub::stop_kind::signal;
		reason.signal = EE_SIGNAL_INTERRUPT;
		reason.thread_id = EE_THREAD_ID;

		if (!trigger.has_value())
			return reason;

		switch (trigger->kind)
		{
			case BreakpointTriggerKind::AddressBreakpoint:
			case BreakpointTriggerKind::StepComplete:
				reason.kind = gdbstub::stop_kind::sw_break;
				reason.signal = EE_SIGNAL_TRAP;
				reason.addr = trigger->addr;
				break;
			case BreakpointTriggerKind::WatchRead:
				reason.kind = gdbstub::stop_kind::watch_read;
				reason.signal = EE_SIGNAL_TRAP;
				reason.addr = trigger->addr;
				break;
			case BreakpointTriggerKind::WatchWrite:
				reason.kind = gdbstub::stop_kind::watch_write;
				reason.signal = EE_SIGNAL_TRAP;
				reason.addr = trigger->addr;
				break;
			case BreakpointTriggerKind::WatchAccess:
				reason.kind = gdbstub::stop_kind::watch_access;
				reason.signal = EE_SIGNAL_TRAP;
				reason.addr = trigger->addr;
				break;
			case BreakpointTriggerKind::ManualPause:
			default:
				reason.kind = gdbstub::stop_kind::signal;
				reason.signal = EE_SIGNAL_INTERRUPT;
				reason.addr = trigger->addr;
				break;
		}

		if (reason.kind == gdbstub::stop_kind::sw_break || reason.kind == gdbstub::stop_kind::watch_read ||
			reason.kind == gdbstub::stop_kind::watch_write || reason.kind == gdbstub::stop_kind::watch_access)
		{
			CBreakPoints::SetSkipFirst(BREAKPOINT_EE, r5900Debug.getPC());
		}

		return reason;
	}

	std::optional<gdbstub::stop_reason> EEGDBStubService::PollStop()
	{
		if (!m_waiting_for_stop)
			return std::nullopt;

		const VMState state = VMManager::GetState();
		if (state == VMState::Running || state == VMState::Resetting || state == VMState::Initializing)
			return std::nullopt;

		gdbstub::stop_reason reason = RunOnCPUThreadBlockingResult([this]() { return BuildStopReasonForPausedState(); });
		m_waiting_for_stop = false;
		m_last_resume_was_step = false;
		{
			std::lock_guard lock(m_mutex);
			m_last_stop_reason = reason;
		}
		return reason;
	}

	std::vector<u64> EEGDBStubService::GetThreadIds() const
	{
		return {EE_THREAD_ID};
	}

	u64 EEGDBStubService::GetCurrentThread() const
	{
		return EE_THREAD_ID;
	}

	gdbstub::target_status EEGDBStubService::SetCurrentThread(u64 tid)
	{
		return (tid == EE_THREAD_ID) ? gdbstub::target_status::ok : gdbstub::target_status::invalid;
	}

	std::optional<u64> EEGDBStubService::GetThreadPC(u64 tid)
	{
		if (tid != EE_THREAD_ID)
			return std::nullopt;

		return RunOnCPUThreadBlockingResult([]() -> u64 { return static_cast<u64>(r5900Debug.getPC()); });
	}

	std::optional<std::string> EEGDBStubService::GetThreadName(u64 tid) const
	{
		if (tid != EE_THREAD_ID)
			return std::nullopt;

		return std::string(EE_THREAD_NAME);
	}

	std::optional<gdbstub::stop_reason> EEGDBStubService::GetThreadStopReason(u64 tid) const
	{
		if (tid != EE_THREAD_ID)
			return std::nullopt;

		std::lock_guard lock(m_mutex);
		return m_last_stop_reason;
	}

	std::optional<gdbstub::host_info> EEGDBStubService::GetHostInfo() const
	{
		gdbstub::host_info info;
		info.triple = EE_TARGET_TRIPLE;
		info.endian = EE_TARGET_ENDIAN;
		info.ptr_size = EE_TARGET_PTR_SIZE;
		info.hostname = EE_TARGET_HOSTNAME;
		info.addressing_bits = EE_TARGET_ADDRESS_BITS;
		info.low_mem_addressing_bits = EE_TARGET_ADDRESS_BITS;
		info.high_mem_addressing_bits = EE_TARGET_ADDRESS_BITS;
		return info;
	}

	std::optional<gdbstub::process_info> EEGDBStubService::GetProcessInfo() const
	{
		gdbstub::process_info info;
		info.pid = EE_PROCESS_ID;
		info.triple = EE_TARGET_TRIPLE;
		info.endian = EE_TARGET_ENDIAN;
		info.ptr_size = EE_TARGET_PTR_SIZE;
		info.ostype = EE_TARGET_OSTYPE;
		return info;
	}

	std::vector<gdbstub::memory_region> EEGDBStubService::GetMemoryMap() const
	{
		std::vector<gdbstub::memory_region> regions;
		regions.reserve(6);

		gdbstub::memory_region ee_ram;
		ee_ram.start = 0x00000000;
		ee_ram.size = static_cast<u64>(Ps2MemSize::ExposedRam);
		ee_ram.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::write | gdbstub::mem_perm::exec;
		ee_ram.name = "EE Main RAM";
		ee_ram.types = {"ram"};
		regions.push_back(std::move(ee_ram));

		gdbstub::memory_region iop_window;
		iop_window.start = 0x1c000000;
		iop_window.size = 0x00800000;
		iop_window.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::write;
		iop_window.name = "IOP Window";
		iop_window.types = {"device"};
		regions.push_back(std::move(iop_window));

		gdbstub::memory_region rom1;
		rom1.start = 0x1e000000;
		rom1.size = Ps2MemSize::Rom1;
		rom1.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::exec;
		rom1.name = "ROM1";
		rom1.types = {"rom"};
		regions.push_back(std::move(rom1));

		gdbstub::memory_region rom2;
		rom2.start = 0x1e400000;
		rom2.size = Ps2MemSize::Rom2;
		rom2.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::exec;
		rom2.name = "ROM2";
		rom2.types = {"rom"};
		regions.push_back(std::move(rom2));

		gdbstub::memory_region bios;
		bios.start = 0x1fc00000;
		bios.size = Ps2MemSize::Rom;
		bios.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::exec;
		bios.name = "BIOS";
		bios.types = {"rom"};
		regions.push_back(std::move(bios));

		gdbstub::memory_region scratch;
		scratch.start = 0x70000000;
		scratch.size = Ps2MemSize::Scratch;
		scratch.perms = gdbstub::mem_perm::read | gdbstub::mem_perm::write | gdbstub::mem_perm::exec;
		scratch.name = "Scratchpad";
		scratch.types = {"ram"};
		regions.push_back(std::move(scratch));

		return regions;
	}

	std::optional<WatchpointKey> EEGDBStubService::MakeWatchpointKey(const gdbstub::breakpoint_request& request) const
	{
		const gdbstub::breakpoint_type type = request.spec.type;
		if (type != gdbstub::breakpoint_type::watch_read &&
			type != gdbstub::breakpoint_type::watch_write &&
			type != gdbstub::breakpoint_type::watch_access)
		{
			return std::nullopt;
		}

		const u64 addr = request.spec.addr;
		const u32 len = request.spec.length;
		if (len == 0 || !IsEEAddressRangeValid(addr, len))
			return std::nullopt;

		const u32 start = standardizeBreakpointAddress(static_cast<u32>(addr));
		const u32 end = standardizeBreakpointAddress(static_cast<u32>(addr + len));
		return WatchpointKey{type, start, end};
	}

	gdbstub::target_status EEGDBStubService::SetBreakpoint(const gdbstub::breakpoint_request& request)
	{
		const gdbstub::breakpoint_type type = request.spec.type;
		if (type == gdbstub::breakpoint_type::software || type == gdbstub::breakpoint_type::hardware)
		{
			if (!IsEEAddressRangeValid(request.spec.addr, 1))
				return gdbstub::target_status::invalid;

			const u32 addr = NormalizeEEBreakpointAddress(request.spec.addr);
			auto [it, inserted] = m_remote_breakpoints.try_emplace(addr, RemoteBreakpointEntry{});
			RemoteBreakpointEntry& entry = it->second;
			if (!inserted)
			{
				entry.refcount++;
				return gdbstub::target_status::ok;
			}

			const bool temp_exists = RunOnCPUThreadBlockingResult([addr]() {
				return CBreakPoints::IsTempBreakPoint(BREAKPOINT_EE, addr);
			});

			if (!temp_exists)
				RunOnCPUThreadBlocking([addr]() { CBreakPoints::AddBreakPoint(BREAKPOINT_EE, addr, true, true); });

			entry.refcount = 1;
			entry.remote_created = !temp_exists;
			return gdbstub::target_status::ok;
		}

		const std::optional<WatchpointKey> key = MakeWatchpointKey(request);
		if (!key.has_value())
			return gdbstub::target_status::unsupported;

		auto [it, inserted] = m_remote_watchpoints.try_emplace(*key, RemoteWatchpointEntry{});
		RemoteWatchpointEntry& entry = it->second;
		if (!inserted)
		{
			entry.refcount++;
			return gdbstub::target_status::ok;
		}

		MemCheckCondition requested_cond = MEMCHECK_READWRITE;
		const gdbstub::target_status cond_status = MemCondFromBreakpointType(key->type, &requested_cond);
		if (cond_status != gdbstub::target_status::ok)
			return cond_status;

		const std::optional<bool> can_reuse_existing = RunOnCPUThreadBlockingResult([&key, requested_cond]() -> std::optional<bool> {
			const auto checks = CBreakPoints::GetMemChecks(BREAKPOINT_EE);
			for (const MemCheck& check : checks)
			{
				if (check.start != key->start || check.end != key->end)
					continue;
				const bool has_break = ((check.result & MEMCHECK_BREAK) != 0);
				const bool has_cond = ((check.memCond & requested_cond) == requested_cond);
				return has_break && has_cond;
			}
			return std::nullopt;
		});

		if (can_reuse_existing.has_value())
		{
			if (!can_reuse_existing.value())
			{
				m_remote_watchpoints.erase(it);
				return gdbstub::target_status::unsupported;
			}

			entry.refcount = 1;
			entry.remote_created = false;
			return gdbstub::target_status::ok;
		}

		RunOnCPUThreadBlocking([&key, requested_cond]() {
			CBreakPoints::AddMemCheck(BREAKPOINT_EE, key->start, key->end, requested_cond, MEMCHECK_BREAK);
		});

		entry.refcount = 1;
		entry.remote_created = true;
		return gdbstub::target_status::ok;
	}

	gdbstub::target_status EEGDBStubService::RemoveBreakpoint(const gdbstub::breakpoint_request& request)
	{
		const gdbstub::breakpoint_type type = request.spec.type;
		if (type == gdbstub::breakpoint_type::software || type == gdbstub::breakpoint_type::hardware)
		{
			if (!IsEEAddressRangeValid(request.spec.addr, 1))
				return gdbstub::target_status::invalid;

			const u32 addr = NormalizeEEBreakpointAddress(request.spec.addr);
			auto it = m_remote_breakpoints.find(addr);
			if (it == m_remote_breakpoints.end())
				return gdbstub::target_status::ok;

			RemoteBreakpointEntry& entry = it->second;
			if (entry.refcount > 1)
			{
				entry.refcount--;
				return gdbstub::target_status::ok;
			}

			if (entry.remote_created)
				RunOnCPUThreadBlocking([addr]() { CBreakPoints::RemoveBreakPoint(BREAKPOINT_EE, addr, true); });

			m_remote_breakpoints.erase(it);
			return gdbstub::target_status::ok;
		}

		const std::optional<WatchpointKey> key = MakeWatchpointKey(request);
		if (!key.has_value())
			return gdbstub::target_status::unsupported;

		auto it = m_remote_watchpoints.find(*key);
		if (it == m_remote_watchpoints.end())
			return gdbstub::target_status::ok;

		RemoteWatchpointEntry& entry = it->second;
		if (entry.refcount > 1)
		{
			entry.refcount--;
			return gdbstub::target_status::ok;
		}

		if (entry.remote_created)
		{
			RunOnCPUThreadBlocking([&key]() { CBreakPoints::RemoveMemCheck(BREAKPOINT_EE, key->start, key->end); });
		}

		m_remote_watchpoints.erase(it);
		return gdbstub::target_status::ok;
	}

	gdbstub::breakpoint_capabilities EEGDBStubService::GetBreakpointCapabilities() const
	{
		gdbstub::breakpoint_capabilities caps;
		caps.software = true;
		caps.hardware = true;
		caps.watch_read = true;
		caps.watch_write = true;
		caps.watch_access = true;
		return caps;
	}

	std::optional<gdbstub::register_info> EEGDBStubService::GetRegisterInfo(int regno)
	{
		if (regno < 0 || regno >= EE_REG_COUNT)
			return std::nullopt;

		gdbstub::register_info info;
		info.bitsize = 64;
		info.encoding = "uint";
		info.format = "hex";
		info.set = "General Purpose Registers";

		if (regno < EE_GPR_COUNT)
		{
			info.name = EE_GPR_NAMES[static_cast<size_t>(regno)];
			if (regno == 29)
				info.generic = "sp";
			return info;
		}

		if (regno == EE_PC_REG)
		{
			info.name = "pc";
			info.generic = "pc";
			return info;
		}
		if (regno == EE_HI_REG)
		{
			info.name = "hi";
			return info;
		}
		if (regno == EE_LO_REG)
		{
			info.name = "lo";
			return info;
		}

		return std::nullopt;
	}

	size_t EERegsCapability::reg_size(int regno)
	{
		return m_service.RegSize(regno);
	}

	gdbstub::target_status EERegsCapability::read_reg(int regno, std::span<std::byte> out)
	{
		return m_service.ReadReg(regno, out);
	}

	gdbstub::target_status EERegsCapability::write_reg(int regno, std::span<const std::byte> data)
	{
		return m_service.WriteReg(regno, data);
	}

	gdbstub::target_status EEMemoryCapability::read_mem(u64 addr, std::span<std::byte> out)
	{
		return m_service.ReadMem(addr, out);
	}

	gdbstub::target_status EEMemoryCapability::write_mem(u64 addr, std::span<const std::byte> data)
	{
		return m_service.WriteMem(addr, data);
	}

	gdbstub::resume_result EERunCapability::resume(const gdbstub::resume_request& request)
	{
		return m_service.Resume(request);
	}

	void EERunCapability::interrupt()
	{
		m_service.Interrupt();
	}

	std::optional<gdbstub::stop_reason> EERunCapability::poll_stop()
	{
		return m_service.PollStop();
	}

	gdbstub::target_status EEBreakpointCapability::set_breakpoint(const gdbstub::breakpoint_request& request)
	{
		return m_service.SetBreakpoint(request);
	}

	gdbstub::target_status EEBreakpointCapability::remove_breakpoint(const gdbstub::breakpoint_request& request)
	{
		return m_service.RemoveBreakpoint(request);
	}

	gdbstub::breakpoint_capabilities EEBreakpointCapability::capabilities()
	{
		return m_service.GetBreakpointCapabilities();
	}

	std::optional<gdbstub::register_info> EERegisterInfoCapability::get_register_info(int regno)
	{
		return m_service.GetRegisterInfo(regno);
	}

	std::vector<u64> EEThreadsCapability::thread_ids()
	{
		return m_service.GetThreadIds();
	}

	u64 EEThreadsCapability::current_thread()
	{
		return m_service.GetCurrentThread();
	}

	gdbstub::target_status EEThreadsCapability::set_current_thread(u64 tid)
	{
		return m_service.SetCurrentThread(tid);
	}

	std::optional<u64> EEThreadsCapability::thread_pc(u64 tid)
	{
		return m_service.GetThreadPC(tid);
	}

	std::optional<std::string> EEThreadsCapability::thread_name(u64 tid)
	{
		return m_service.GetThreadName(tid);
	}

	std::optional<gdbstub::stop_reason> EEThreadsCapability::thread_stop_reason(u64 tid)
	{
		return m_service.GetThreadStopReason(tid);
	}

	std::optional<gdbstub::host_info> EEIdentityCapability::get_host_info()
	{
		return m_service.GetHostInfo();
	}

	std::optional<gdbstub::process_info> EEIdentityCapability::get_process_info()
	{
		return m_service.GetProcessInfo();
	}

	std::vector<gdbstub::memory_region> EEMemoryLayoutCapability::memory_map()
	{
		return m_service.GetMemoryMap();
	}

	EEGDBStubService s_service;
} // namespace

bool IsInitialized()
{
	return s_service.IsInitialized();
}

u16 GetPort()
{
	return s_service.GetPort();
}

bool GetPauseOnConnect()
{
	return s_service.GetPauseOnConnect();
}

bool Initialize(const Config& config)
{
	return s_service.Initialize(config);
}

void Deinitialize()
{
	s_service.Deinitialize();
}

#else

bool IsInitialized()
{
	return false;
}

u16 GetPort()
{
	return 0;
}

bool GetPauseOnConnect()
{
	return false;
}

bool Initialize(const Config& config)
{
	Console.Warning("EEGDBStub: Requested initialization but feature was disabled at build time.");
	return false;
}

void Deinitialize()
{
}

#endif
} // namespace EEGDBStub

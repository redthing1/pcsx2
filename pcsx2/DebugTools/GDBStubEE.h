// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Types.h"

namespace EEGDBStub
{
	struct Config
	{
		u16 port = 0;
		bool pause_on_connect = true;
	};

	bool IsInitialized();
	u16 GetPort();
	bool GetPauseOnConnect();
	bool Initialize(const Config& config);
	void Deinitialize();
} // namespace EEGDBStub

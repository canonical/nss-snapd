# SPDX-FileCopyrightText: 2026 Zygmunt Krynicki
# SPDX-License-Identifier: LGPL-3.0-only

define UBUNTU_CLOUD_INIT_USER_DATA_TEMPLATE
$(CLOUD_INIT_USER_DATA_TEMPLATE)
packages:
- build-essential
- binutils
- make
- valgrind
endef

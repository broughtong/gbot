#pragma once
#include <atomic>

// shared quit flag
inline std::atomic<bool> force_quit{false};

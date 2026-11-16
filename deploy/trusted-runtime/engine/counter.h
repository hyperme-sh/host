#pragma once
#include <cstdint>
#include <limits>
#include <stdexcept>

// Called only by the measured engine after a completed decode or sample.
// This CPU profile creates a fresh context and does not run a draft model.
struct meter_counts {
    int64_t processed_input = 0, accepted_output = 0, hidden_output = 0;
    int64_t cache_hits = 0, rejected_speculative = 0;
    bool uncertain = false;
    template<class Decode> void input(int64_t count, Decode decode) {
        if (count <= 0 || count > 32 || processed_input > std::numeric_limits<int64_t>::max()-count) throw std::runtime_error("count");
        if (!decode()) { uncertain = true; throw std::runtime_error("decode"); }
        processed_input += count;
    }
    void accepted(bool hidden) {
        if (accepted_output == std::numeric_limits<int64_t>::max()) throw std::runtime_error("count");
        ++accepted_output;
        if (hidden) ++hidden_output;
    }
};

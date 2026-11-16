#include "counter.h"
#include <cassert>
int main() {
    meter_counts c;
    c.input(5, []{return true;});
    for(int i=0;i<9;++i)c.accepted(i<7);
    assert(c.processed_input+c.accepted_output==14 && c.hidden_output==7);
    assert(c.cache_hits==0 && c.rejected_speculative==0);
    try { c.input(2, []{return false;}); assert(false); } catch (...) {}
    assert(c.uncertain && c.processed_input==5);
}

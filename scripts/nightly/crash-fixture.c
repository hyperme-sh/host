/* Isolated nightly model substitution; never a production model executable. */
#include <unistd.h>
int main(void) {
    /* Keep the private canaries on the crashing thread's captured stack. */
    volatile char private_marker[] = "PROMPT-PRIVATE-MARKER FILE-CONTENTS-MARKER";
    for (;;) { (void)private_marker[0]; pause(); }
}

/* Isolated nightly model substitution; never a production model executable. */
#include <unistd.h>
static volatile char private_marker[] = "PROMPT-PRIVATE-MARKER FILE-CONTENTS-MARKER";
int main(void) { (void)private_marker[0]; for (;;) pause(); }

// Comprehensive status bar configuration for dwmblocks-dnet
// Modify this file to change what commands output to your statusbar, and recompile using the make command.

static const Block blocks[] = {
	/*Icon*/	/*Command*/		/*Update Interval*/	/*Update Signal*/
	{"Mem:", "free -h | awk '/^Mem/ { print $3 }' | sed s/i//g", 5, 0},
	{"", "pacman -Qu | wc -l", 3000, 0},
	{"", "date '+%I:%M %p'", 5, 0},
};

// sets delimiter between status commands. NULL character ('\0') means no delimiter.
static char delim[] = " | ";
static unsigned int delimLen = 3;

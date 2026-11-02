# Run build.sh from a disposable HOME with PMG_CONFIG_DIR and PMG_CACHE_DIR set.
# Setup edits that HOME's shell files. The install uses live npm and analysis APIs.
Require pmg
Require npm
Output pmg-intro.gif
Set Shell bash
Set FontSize 25
Set Width 1500
Set Height 1000
Set WindowBar Colorful
Set TypingSpeed 25ms
Type "pmg setup install"
Enter
Sleep 3s
Type 'source "$PMG_CONFIG_DIR/pmg.rc"'
Enter
Sleep 1s
Type "npm install --ignore-scripts safedep-test-pkg@0.1.3"
Enter
Sleep 18s
Screenshot "../assets/pmg-banner.png"

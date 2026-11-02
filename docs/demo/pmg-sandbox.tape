# Run from a disposable HOME with PMG_CONFIG_DIR and PMG_CACHE_DIR set.
# The recording shows CI=true explicitly. It does not use a PTY for the child.
Require pmg
Require npm
Require node
Output pmg-sandbox.gif
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
Type "export CI=true"
Enter
Type "pmg config set sandbox.enabled true"
Enter
Sleep 2s
Type `npm exec -- node -e "try{require('child_process').execSync('curl --version',{stdio:'inherit'})}catch(e){process.exit(1)}"`
Enter
Sleep 6s

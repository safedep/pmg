Output pmg-sandbox.gif

Set FontSize 28
Set Width 1400
Set Height 1000

Set WindowBar Colorful

Hide
Type "export CI=true"
Enter

Type "clear"
Enter

Sleep 0.5s
Show

Type "pmg setup install"
Enter
Sleep 2s

Enter

Type "source ~/.pmg.rc"
Enter
Sleep 2s

Enter

Type `npm exec -- \` Enter
Type `node -e "require('child_process').execSync('curl')" \` Enter
Type ` 2>&1 | head -n 8` Enter

Sleep 5s


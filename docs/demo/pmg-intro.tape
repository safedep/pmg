Output pmg-intro.gif
Set Theme "TokyoNightStorm"

Set FontSize 26
Set Width 1400
Set Height 600

Set WindowBar Colorful

Type "pmg setup install"
Enter
Sleep 3s

Type "clear" Sleep 1s Enter

Type "pmg npm install safedep-test-pkg@0.1.3"
Enter
Sleep 5s

Type "clear" Sleep 1s Enter

Type `pmg npm exec -- \` Enter
Type `node -e "require('child_process').execSync('curl')" \` Enter
Type ` 2>&1 | head -n 8` Enter

Sleep 4s


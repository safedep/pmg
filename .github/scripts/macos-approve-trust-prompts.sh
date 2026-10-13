#!/usr/bin/env bash
# Approves the macOS dialog "You are making changes to the System Certificate
# Trust Settings" on a CI runner. macOS shows it when a process changes or
# removes admin trust settings that exist, also under sudo. A person types an
# admin password there. The runner has no person, so the trust store commands
# of pmg wait until the job times out.
#
# The script clicks only that dialog. It reads the admin name and password
# from PMG_CI_ADMIN_USER and PMG_CI_ADMIN_PASSWORD, so the password is not on a
# command line.
set -u

: "${PMG_CI_ADMIN_USER:?set PMG_CI_ADMIN_USER}"
: "${PMG_CI_ADMIN_PASSWORD:?set PMG_CI_ADMIN_PASSWORD}"

while true; do
  result="$(osascript 2>&1 <<'EOF'
set pw to system attribute "PMG_CI_ADMIN_PASSWORD"
set usr to system attribute "PMG_CI_ADMIN_USER"
tell application "System Events"
  if not (exists process "SecurityAgent") then return ""
  tell process "SecurityAgent"
    repeat with w in windows
      set texts to value of every static text of w
      if (texts as text) contains "System Certificate Trust Settings" then
        set fields to every text field of w
        if (count of fields) is 2 then
          set value of item 1 of fields to usr
          set value of item 2 of fields to pw
        else
          set value of item 1 of fields to pw
        end if
        click button "Update Settings" of w
        return "approved"
      end if
    end repeat
  end tell
end tell
return ""
EOF
)"
  if [ -n "$result" ]; then
    echo "$(date -u +%H:%M:%S) ${result}"
  fi
  sleep 1
done

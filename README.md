# Camect Python client library
==============================

## Installation
<pre>
pip3 install camect-py
</pre>

## Usage
Please open https://local.home.camect.com/ in browser, sign in as admin and accept TOS before
you proceed.
<pre>
import camect
home = camect.Home("camect.local:443", "admin", "xxx")
home.get_name()
home.add_event_listener(lambda evt: print(evt))
for cam in home.list_cameras():
&nbsp;&nbsp;&nbsp;&nbsp;print("%s(%s) @%s(%s)" % (cam["name"], cam["make"], cam["ip_addr"], cam["mac_addr"]))
</pre>

### Disable / enable alerts
<pre>
import camect
home = camect.Home("camect.local:443", "admin", "xxx")
home.disable_alert(["yyy"], "testing")
....
home.enable_alert(["yyy"], "testing")
</pre>

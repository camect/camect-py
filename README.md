# Camect Python client library
==============================

The Camect [Smart Camera Hub](https://camect.com/) is an advanced network video recorder that uses
AI (Artificial Intelligence), private local video storage, and secure remote access to the networked
security cameras in your home. It plugs into your home network and provides 24×7 recording, viewing
from your home network, and AI-powered smart alert detection and review via the app.
You can learn more about camect at [camect.com](https://camect.com/).

## Installation
<pre>
pip3 install camect-py
</pre>

## Usage
Please open https://local.home.camect.com/ in browser, sign in as admin and accept TOS before
you proceed.
<pre>
import camect
hub = camect.Hub("camect.local:443", "admin", "xxx")
hub.get_name()
hub.add_event_listener(lambda evt: print(evt))
for cam in home.list_cameras():
&nbsp;&nbsp;&nbsp;&nbsp;print("%s(%s) @%s(%s)" % (cam["name"], cam["make"], cam["ip_addr"], cam["mac_addr"]))
</pre>

### Disable / enable alerts
<pre>
import camect
hub = camect.Hub("camect.local:443", "admin", "xxx")
hub.disable_alert(["yyy"], "testing")
....
hub.enable_alert(["yyy"], "testing")
</pre>

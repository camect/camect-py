# Camect Python client library
============================

## Installation
<pre>
pip install camect-py
</pre>

## Usage
<pre>
import camect
home = camect.Home("camect.local:9443", "admin", "xxx")
home.get_name()
home.add_event_listener(lambda evt: print(evt))
</pre>

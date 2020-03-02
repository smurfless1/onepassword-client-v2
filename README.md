# OnePassword python client
Python wrapper around 1Password password manager for usage within python scripts and
Jupyter Notebooks. Developed by Data Scientists from Wandera to be used within both 
research and python services use cases.


## Installation
```bash
pip install 1password
```


## Basic Usage
Currently fully tested on Mac OS.

On first usage users will be asked for both the enrolled email, secret key and master 
password. Mac OS users will also be prompted with installation windows to ensure you have the latest version of `op`.

For all following usages you will only be asked for a master password.

You will be given 3 attempts and then pointed to reset password documentation or alternatively you can
restart your kernel.

No passwords are stored in memory without encryption.

```python
from onepassword import OnePassword
import json

op = OnePassword()

# List all vaults 
json.loads(op.list_vaults())

# List all items in a vault, default is Private
op.get_items()
```



## Roadmap
- Fix and test Linux implementation
- Add UTs
- Add test docker image
- Align response types into JSON / lists instead of JSON strings
- Ensure full functionality of CLI in python
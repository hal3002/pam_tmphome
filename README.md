pam_tmphome
===========

PAM module to dynamically create and destroy home directories for shared accounts.

Installation:
-------------
I've only tested that this builds on FreeBSD and Ubuntu
>make<br />
>make install

Usage:
------
* Make the directory to store the temporary homes
> mkdir /temporary

* Add the pam module to /etc/pam.d/sshd (or any other pam config you want to use)
> session		optional		pam_tmphome.so

* Finally, set your target user's home to /temporary
> user:*:1000:1000:Temporary user:/temporary:/bin/csh

Note:
-----
Part of this code copies directly from pam_mkhomedir so I copied their license because
I don't know jackshit about software licenses and I honestly don't care what anyone
does with this code.

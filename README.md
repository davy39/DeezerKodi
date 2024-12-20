# DeezerKodi

This is an unofficial Deezer addon for Kodi.  
It works with all kind of deezer accounts.  
Streaming is limited to 128kb/s for free accounts, but can play up to flac for premium's.  
This addon works for personal and family accounts (profiles are usable).  
It supports access to your playlists. Searching for tracks, albums and artists is also implemented.
Let me know if there is a particular feature you want to see implemented.  

# Installation

* Download
  the [latest release zip file](https://raw.githubusercontent.com/Valentin271/DeezerKodi/master/plugin.audio.deezer/plugin.audio.deezer-2.0.5.zip)
  located at `plugin.audio.deezer/plugin.audio.deezer-x.y.z.zip`.
* Move it to your kodi box.
* Install it by selecting `'Install from zip file'` in the addon menu.

And that's all, it should be updated automatically on every release.

##### Note:

If you previously installed kubatek94's DeezerKodi addon, you should uninstall it first.

### Compatibility

This addon has been tested with Kodi 19 and 20.
Tests where done on Ubuntu, but the addon should work on every device.  
If you have any compatibility issue, please refer to the Issues section.

[Version 1.0.1](https://raw.githubusercontent.com/Valentin271/DeezerKodi/master/plugin.audio.deezer/plugin.audio.deezer-1.0.1.zip)
is the latest version supporting Kodi 18.

# Limitations

Since Deezer API doesn't give profiles for family accounts, the workaround include asking for followings of the main
account.
So if you follow anyone on Deezer, they will appear on your family profiles.

# Issues

If you have any problem with the addon, feel free to open a
new [issue](https://github.com/Valentin271/DeezerKodi/issues).  
*Provide at least the [Kodi log file](https://kodi.wiki/view/Log_file) as an attachment (DON'T directly post it).*


<br>

## Credits

This addon is forked from [kubatek94](https://github.com/kubatek94)'
s [DeezerKodi repo](https://github.com/kubatek94/DeezerKodi).
Only the streaming API, icon and fanart have been reused.

Auth and decryption are adapted from [orpheusdl-deezer](https://github.com/TheKVT/orpheusdl-deezer).
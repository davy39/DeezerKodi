import xbmcgui
import xbmcplugin
import xbmcvfs
from app.actions.base_actions import BaseActions
from app.http import Api
from lib.helpers.logger import Logger


class TracksActions(BaseActions):
    """Holds tracks related actions"""

    @classmethod
    def play(cls, identifiant):
        """
        Get and return the streaming url of the track with the given ID.

        :param identifiant: ID of the track to stream
        :return: track's stream url
        """
        # Get stream url
        url = Api.instance().request_streaming(identifiant)
        if url.startswith('http'):
            # Create a path to download stream       
            path = xbmcvfs.translatePath(f'special://temp/deezer-temp.mp3')
            # Download and decrypt stream
            Api.instance().dl_track(identifiant, url, path)
            # Create an item to give to kodi's player
            item = xbmcgui.ListItem(path=path)
            # Send the item to Kodi's player
            xbmcplugin.setResolvedUrl(cls.app.args().addon_handle, True, listitem=item)
        else:
            Logger.warn("Unable to get url of track " + identifiant)
            xbmcgui.Dialog().notification(
                "Unplayable track",
                "Track " + identifiant + " cannot be played.",
                xbmcgui.NOTIFICATION_WARNING,
                sound=False
            )
            xbmcplugin.setResolvedUrl(cls.app.args().addon_handle, False, xbmcgui.ListItem())
        return []

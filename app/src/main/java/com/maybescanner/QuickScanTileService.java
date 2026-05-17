package com.maybescanner;

import android.content.Intent;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

public class QuickScanTileService extends TileService {
    @Override public void onStartListening() {
        Tile tile = getQsTile();
        if (tile != null) {
            tile.setLabel("Edge Scan");
            tile.setSubtitle("Start preset");
            tile.setState(Tile.STATE_INACTIVE);
            tile.updateTile();
        }
    }

    @Override public void onClick() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.setAction(MainActivity.ACTION_QUICK_SCAN);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivityAndCollapse(intent);
    }
}

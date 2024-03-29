/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2005, 2006, 2007, 2009, 2010, 2013, 2014, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */

package com.zimbra.clam;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;

public class ClamScannerConfig {

    private final boolean mEnabled;
    
    private final String[] mURL;

    public ClamScannerConfig() throws ServiceException {
        Server serverConfig = Provisioning.getInstance().getLocalServer();
        mEnabled = serverConfig.getBooleanAttr(Provisioning.A_zimbraAttachmentsScanEnabled, false);
        mURL = serverConfig.getAttachmentsScanURL();
    }

    public boolean getEnabled() {
        return mEnabled;
    }
    
    public String[] getURL() {
        return mURL;
    }
}

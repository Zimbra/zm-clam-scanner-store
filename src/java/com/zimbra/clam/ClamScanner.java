/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2005, 2006, 2007, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
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

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.UnknownHostException;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HostAndPort;
import com.zimbra.common.io.TcpServerInputStream;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.Log;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.service.mail.UploadScanner;

public class ClamScanner extends UploadScanner{

    private static final String DEFAULT_URL = "clam://localhost:3310/";

    private static final Log LOG = ZimbraLog.extensions;

    private boolean mInitialized;

    private String mClamdHost;

    private int mClamdPort;

    public ClamScanner() {
    }

    @Override
    public void setURL(String urlArg) throws MalformedURLException {
        if (urlArg == null) {
            urlArg = DEFAULT_URL;
        }

        String protocolPrefix = "clam://";
        if (!urlArg.toLowerCase().startsWith(protocolPrefix)) {
            throw new MalformedURLException("invalid clamd url " + urlArg);
        }
        try {
            if (urlArg.lastIndexOf('/') > protocolPrefix.length()) {
                urlArg = urlArg.substring(0, urlArg.lastIndexOf('/'));
            }
            HostAndPort hostPort = HostAndPort.fromString(urlArg.substring(protocolPrefix.length()));
            hostPort.requireBracketsForIPv6();
            mClamdPort = hostPort.getPort();
            mClamdHost = hostPort.getHost();
        } catch (IllegalArgumentException iae) {
            LOG.error("cannot parse clamd url due to illegal arg exception", iae);
            throw new MalformedURLException("cannot parse clamd url due to illegal arg exception: " + iae.getMessage());
        }

        mInitialized = true;
    }

    @Override
    protected Result accept(byte[] array, StringBuffer info) {
        if (!mInitialized) {
            return ERROR;
        }

        try {
            return accept0(array, null, info);
        } catch (Exception e) {
            LOG.error("exception communicating with clamd", e);
            return ERROR;
        }
    }

    @Override
    protected Result accept(InputStream is, StringBuffer info) {
        if (!mInitialized) {
            return ERROR;
        }

        try {
            return accept0(null, is, info);
        } catch (Exception e) {
            LOG.error("exception communicating with clamd", e);
            return ERROR;
        }
    }

    private static final byte[] lineSeparator = { '\r', '\n' };

    private Result accept0(byte[] data, InputStream is, StringBuffer info) throws UnknownHostException, IOException {
        Socket commandSocket = null;
        Socket dataSocket = null;

        try {
            if (LOG.isDebugEnabled()) { LOG.debug("connecting to " + mClamdHost + ":" + mClamdPort); }
            commandSocket = new Socket(mClamdHost, mClamdPort);

            BufferedOutputStream out = new BufferedOutputStream(commandSocket.getOutputStream());
            TcpServerInputStream in = new TcpServerInputStream(commandSocket.getInputStream());

            if (LOG.isDebugEnabled()) { LOG.debug("writing STREAM command"); }
            out.write("STREAM".getBytes("iso-8859-1"));
            out.write(lineSeparator);
            out.flush();

            if (LOG.isDebugEnabled()) { LOG.debug("reading PORT"); }
            // REMIND - should have timeout's on this...
            String portLine = in.readLine();
            if (portLine == null) {
                throw new ProtocolException("EOF from clamd when looking for PORT repsonse");
            }
            if (!portLine.startsWith("PORT ")) {
                throw new ProtocolException("Got '" + portLine + "' from clamd, was expecting PORT <n>");
            }
            int port = 0;
            try {
                port = Integer.valueOf(portLine.substring("PORT ".length())).intValue();
            } catch (NumberFormatException nfe) {
                throw new ProtocolException("No port number in: " + portLine);
            }

            if (LOG.isDebugEnabled()) { LOG.debug("stream connect to " + mClamdHost + ":" + port); }
            dataSocket = new Socket(mClamdHost, port);
            if (data != null) {
                dataSocket.getOutputStream().write(data);
                if (LOG.isDebugEnabled()) { LOG.debug("wrote " + data.length + " bytes"); }
            } else {
                long count = ByteUtil.copy(is, false, dataSocket.getOutputStream(), false);
                if (LOG.isDebugEnabled()) { LOG.debug("copied " + count + " bytes"); }
            }
            dataSocket.close();

            if (LOG.isDebugEnabled()) { LOG.debug("reading result"); }
            String answer = in.readLine();
            if (answer == null) {
                throw new ProtocolException("EOF from clamd when looking for result");
            }
            info.setLength(0);
            if (answer.startsWith("stream: ")) {
                answer = answer.substring("stream: ".length());
            }
            info.append(answer);
            if (answer.equals("OK")) {
                return ACCEPT;
            } else {
                return REJECT;
            }
        } finally {
            if (dataSocket != null && !dataSocket.isClosed()) {
                LOG.warn("deffered close of stream connection");
                dataSocket.close();
            }
            if (commandSocket != null) {
                commandSocket.close();
            }
        }
    }

    @Override
    public boolean isEnabled() {
        return mInitialized;
    }

    @VisibleForTesting
    String getClamdHost() {
        return mClamdHost;
    }

    @VisibleForTesting
    int getClamdPort() {
        return mClamdPort;
    }

}


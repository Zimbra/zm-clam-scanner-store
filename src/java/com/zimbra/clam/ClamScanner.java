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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HostAndPort;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.util.Log;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.service.mail.UploadScanner;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class ClamScanner extends UploadScanner {

    private static final String RESULT_PREFIX = "stream: ";
    private static final String ANSWER_OK = "OK";

    private static final int SOCKET_TIMEOUT = 2000;
    private static final int CHUNK_SIZE = 2048;

    private static final String DEFAULT_URL = "clam://localhost:3310/";

    private static final Log LOG = ZimbraLog.extensions;
    private final int chunkSize;
    private final int socketTimeout;
    private boolean mInitialized;
    private String mClamdHost;
    private int mClamdPort;

    public ClamScanner() {
        socketTimeout = (LC.clamav_socket_timeout.intValue() > 0) ? LC.clamav_socket_timeout.intValue() : SOCKET_TIMEOUT;
        chunkSize = (LC.clamav_scan_data_chunk_size.intValue() > 0) ? LC.clamav_scan_data_chunk_size.intValue() : CHUNK_SIZE;
        if (LOG.isDebugEnabled()) {
            LOG.debug("socketTimeout: " + socketTimeout + ", chunkSize: " + chunkSize);
        }
    }

    private static byte[] readAll(InputStream is) throws IOException {
        ByteArrayOutputStream tmp = new ByteArrayOutputStream();

        byte[] buf = new byte[2000];
        int read = 0;
        do {
            read = is.read(buf);
            tmp.write(buf, 0, read);
        } while ((read > 0) && (is.available() > 0));
        return tmp.toByteArray();
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

    private Result accept0(byte[] data, InputStream inputStream, StringBuffer info) throws UnknownHostException, IOException {
        Socket socket = null;
        OutputStream outStream = null;
        InputStream socketInputStream = null;
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("connecting to " + mClamdHost + ":" + mClamdPort);
            }
            socket = new Socket(mClamdHost, mClamdPort);
            outStream = new BufferedOutputStream(socket.getOutputStream());
            socket.setSoTimeout(socketTimeout);
            LOG.debug("writing zINSTREAM command");
            outStream.write("zINSTREAM\0".getBytes(StandardCharsets.ISO_8859_1));
            outStream.flush();

            // if byte array passed as input instead of inputStream
            if (data != null && inputStream == null) {
                inputStream = new ByteArrayInputStream(data);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("sending data for scanning, chunkSize: " + chunkSize);
            }
            byte[] buffer = new byte[chunkSize];
            socketInputStream = socket.getInputStream();
            int read = inputStream.read(buffer);
            while (read >= 0) {
                byte[] chunkSize = ByteBuffer.allocate(4).putInt(read).array();
                outStream.write(chunkSize);
                outStream.write(buffer, 0, read);
                if (socketInputStream.available() > 0) {
                    byte[] reply = readAll(socketInputStream);
                    throw new IOException("Reply from server: " + new String(reply, StandardCharsets.ISO_8859_1));
                }
                read = inputStream.read(buffer);
            }
            outStream.write(new byte[]{0, 0, 0, 0});
            outStream.flush();
            LOG.debug("reading result");

            String answer = new String(readAll(socketInputStream), StandardCharsets.ISO_8859_1);
            if (LOG.isDebugEnabled()) {
                LOG.debug("ClamAV response =" + answer);
            }
            if (StringUtil.isNullOrEmpty(answer)) {
                throw new ProtocolException("EOF from clamd when looking for result");
            }
            info.setLength(0);
            String extractedAns = "";
            if (answer.startsWith(RESULT_PREFIX)) {
                extractedAns = answer.substring(RESULT_PREFIX.length()).trim();
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("ClamAV extracted response: " + extractedAns);
            }
            info.append(extractedAns);
            if (ANSWER_OK.equals(extractedAns)) {
                return ACCEPT;
            } else {
                return REJECT;
            }
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                LOG.debug("Exception occurred while closing socket = {} " + e.getMessage());
            }
            try {
                if (socketInputStream != null) {
                    socketInputStream.close();
                }
            } catch (IOException e) {
                LOG.debug("Exception occurred while closing input streams = {} " + e.getMessage());
            }
            try {
                if (outStream != null) {
                    outStream.close();
                }
            } catch (IOException e) {
                LOG.debug("Exception occurred while closing output streams = {} " + e.getMessage());
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


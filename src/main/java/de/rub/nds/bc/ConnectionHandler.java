package de.rub.nds.bc;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.tls.TlsServerProtocol;

public class ConnectionHandler implements Runnable {

    private final static Logger LOGGER = LogManager.getLogger(ConnectionHandler.class);

    private final TlsServerProtocol tlsServerProtocol;

    /**
     * ConnectionHandler constructor
     * 
     * @param socket
     *            - The socket of the connection
     */
    public ConnectionHandler(final TlsServerProtocol tlsServerProtocol) {
	this.tlsServerProtocol = tlsServerProtocol;
    }

    @Override
    public void run() {

	LOGGER.debug("new Thread started");

	try {
	    final BufferedReader br = new BufferedReader(new InputStreamReader(tlsServerProtocol.getInputStream()));
	    final BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(tlsServerProtocol.getOutputStream()));
	    String line = "";
//	    while ((line = br.readLine()) != null) {
		LOGGER.debug(line);
		bw.write("HTTP/1.1 200 OK\n"+
						"Date: Sun, 18 Oct 2009 08:56:53 GMT\n"+
				"Last-Modified: Sat, 20 Nov 2004 07:16:26 GMT\n"+
				"ETag: 10000000565a5-2c-3e94b66c2e680\n" +
				"Accept-Ranges: bytes\n"+
				"Content-Length: 44\n"+
				"Connection: close\n"+
				"Content-Type: text/html\n"+
				"\r\n\r\n"+
				"<html><body><h1>It works!</h1></body></html>\n");
		bw.flush();
//	    }
	} catch (IOException e) {
	    LOGGER.debug(e.getLocalizedMessage(), e);
	} finally {
	    try {
	    tlsServerProtocol.close();
	    } catch (final IOException ioe) {
		LOGGER.debug(ioe.getLocalizedMessage(), ioe);
	    }
	}
    }
}
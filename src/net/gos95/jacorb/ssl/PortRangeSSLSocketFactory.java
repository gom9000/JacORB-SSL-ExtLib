/*
 * @(#)PortRangeSSLSocketFactory.java
 *                       ________.________
 *   ____   ____  ______/   __   \   ____/
 *  / ___\ /  _ \/  ___/\____    /____  \ 
 * / /_/  >  <_> )___ \    /    //       \
 * \___  / \____/____  >  /____//______  /
 * /____/            \/                \/ 
 * Copyright (c) 2020 Alessandro Fraschetti (gos95@gommagomma.net).
 *
 * This file is part of jacorb-ssl-extlib:
 * https://github.com/gom9000/jacorb-ssl-extlib
 * http://www.gommagomma.net/software/jacorb-ssl-extlib
 *
 * jacorb-ssl-extlib is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * jacorb-ssl-extlib is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with jacorb-ssl-extlib. If not, see <http://www.gnu.org/licenses/>.
 */


package net.gos95.jacorb.ssl;


import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Security;
import java.util.StringTokenizer;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.logger.Logger;
import org.jacorb.security.ssl.sun_jsse.KeyStoreUtil;


/**
 * A SocketFactory implementation that allows to create
 * sockets that support SSL and port range.
 */
public class PortRangeSSLSocketFactory
extends org.jacorb.orb.factory.PortRangeFactory 
implements org.jacorb.orb.factory.SocketFactory
{
    public static final String MIN_PROP = "jacorb.ssl.socket_factory.port.min";
    public static final String MAX_PROP = "jacorb.ssl.socket_factory.port.max";

    private SocketFactory factory = null;
    private String[] cipher_suites = null;
    private TrustManager trustManager = null;

    private boolean trusteesFromKS = false;
    private short clientSupportedOptions = 0;
    private String keystore_location = null;
    private String keystore_passphrase = null;
    private Logger logger;


    public PortRangeSSLSocketFactory(org.jacorb.orb.ORB orb) 
    throws ConfigurationException
    {
            configure(orb.getConfiguration());
    }
 

    @Override
    public void configure(Configuration c)
    throws ConfigurationException
    {
        configuration = (org.jacorb.config.Configuration)c;
        logger = configuration.getNamedLogger("jacorb.security.jsse");

        portMin = getPortProperty(MIN_PROP);
        portMax = getPortProperty(MAX_PROP);

        if (portMin > portMax)
        {
            throw new ConfigurationException("PortRangeSSLFactory: minimum port number not less than or equal to maximum");
        }

        trusteesFromKS = configuration.getAttributeAsBoolean("jacorb.security.jsse.trustees_from_ks", false);

        keystore_location = configuration.getAttribute("jacorb.security.keystore", "UNSET");

        keystore_passphrase = configuration.getAttribute("jacorb.security.keystore_password", "UNSET");

        clientSupportedOptions = Short.parseShort(configuration.getAttribute("jacorb.security.ssl.client.supported_options", "0"), 16);

        try
        {
            trustManager = (TrustManager)((org.jacorb.config.Configuration)configuration).getAttributeAsObject("jacorb.security.ssl.client.trust_manager");
        }
        catch (ConfigurationException ce)
        {
            if (logger.isErrorEnabled())
            {
                logger.error("TrustManager object creation failed. Please check value of property "
                        + "'jacorb.security.ssl.client.trust_manager'. Current value: " 
                        + configuration.getAttribute("jacorb.security.ssl.client.trust_manager", ""), ce); 
            }
        }

        try
        {
            factory = createSocketFactory();
        }
        catch(Exception e)
        {
            if (logger.isWarnEnabled())
                logger.warn("Exception", e );
        }

        if(factory == null)
        {
            if (logger.isErrorEnabled())
                logger.error("Unable to create PortRangeSSLSocketFactory!" );
            throw new ConfigurationException("Unable to create PortRangeSSLSocketFactory!");
        }

        // Andrew T. Finnell / Change made for e-Security Inc. 2002
        // We need to obtain all the cipher suites to use from the 
        // properties file.
        String cipher_suite_list = configuration.getAttribute("jacorb.security.ssl.server.cipher_suites", null);

        if (cipher_suite_list != null)
        {
            StringTokenizer tokenizer = new StringTokenizer(cipher_suite_list, ",");

            // Get the number of ciphers in the list
            int tokens = tokenizer.countTokens();

            if (tokens > 0)
            {
                // Create an array of strings to store the ciphers
                cipher_suites = new String[tokens];

                // This will fill the array in reverse order but that doesn't
                // matter
                while(tokenizer.hasMoreElements())
                {
                    cipher_suites[--tokens] = tokenizer.nextToken();
                }
            }
        }
    }


    @Override
    public Socket createSocket(String host, int port)
    throws IOException, UnknownHostException
    {
        int localPort;
        InetAddress localHost = InetAddress.getLocalHost();
        SSLSocket s;

        for (localPort = portMin; localPort <= portMax; localPort++)
        {
            try
            {
                s = (SSLSocket)factory.createSocket(host, port, localHost, localPort);
                if (logger.isDebugEnabled())
                    logger.debug("PortRangeSSLSocketFactory: Created socket at " + ":" + localPort);

                // Andrew T. Finnell
                // We need a way to enable the cipher suites that we would like to use
                // We should obtain these from the properties file
                if(cipher_suites != null)
                {
                    s.setEnabledCipherSuites(cipher_suites);
                }

                return s;

            }
            catch (IOException ex)
            {
                // Ignore and continue
            }
        }

        if (logger.isDebugEnabled())
            logger.debug("Cannot bind socket between ports " + portMin + " and " + portMax + " to target " + host + ":" + port);

        throw new BindException ("PortRangeSSLSocketFactory: no free port between " + portMin + " and " + portMax);

    }


    @Override
    public boolean isSSL(Socket s)
    {
        return (s instanceof SSLSocket); 
    }


    private SocketFactory createSocketFactory() 
    throws IOException, java.security.GeneralSecurityException
    {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());

        KeyManagerFactory kmf = null;
        KeyStore key_store = null;

        if(trusteesFromKS || (clientSupportedOptions& 0x40) != 0)
        {            
            key_store = KeyStoreUtil.getKeyStore(keystore_location, keystore_passphrase.toCharArray());
            //only add own credentials, if establish trust in
            //client is supported
            if( (clientSupportedOptions & 0x40) != 0) 
            {        
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(key_store, keystore_passphrase.toCharArray());
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");

        if(key_store != null && trusteesFromKS)
        {
            //take trusted certificates from keystore
            if (logger.isInfoEnabled())
                logger.info("Loading certs from keystore " + key_store);
            tmf.init(key_store);
        }
        else
        {
            tmf.init((KeyStore)null);
        }

        TrustManager[] trustManagers;

        if (trustManager == null)
        {
            trustManagers = tmf.getTrustManagers();
        }
        else
        {
            if (logger.isDebugEnabled())
            {
                logger.debug("Setting user specified client TrustManger : " + trustManager.getClass().toString());
            }
            trustManagers = new TrustManager[] { trustManager };
        }

        SSLContext ctx = SSLContext.getInstance( "TLS" );

        ctx.init((kmf == null)? null : kmf.getKeyManagers(), trustManagers, null);

        return ctx.getSocketFactory();
    }
}

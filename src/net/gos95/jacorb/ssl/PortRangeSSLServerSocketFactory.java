/*
 * @(#)PortRangeSSLServerSocketFactory.java
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
import java.net.ServerSocket;
import java.security.KeyStore;
import java.security.Security;
import java.util.StringTokenizer;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.avalon.framework.configuration.Configuration;
import org.apache.avalon.framework.configuration.ConfigurationException;
import org.apache.avalon.framework.logger.Logger;
import org.jacorb.security.ssl.sun_jsse.KeyStoreUtil;


/**
 * A ServerSocketFactory implementation that allows to create
 * server sockets that support SSL and port range.
 */
public class PortRangeSSLServerSocketFactory
extends org.jacorb.orb.factory.PortRangeFactory
implements org.jacorb.orb.factory.SSLServerSocketFactory
{
    public static final String MIN_PROP = "jacorb.ssl.server_socket_factory.port.min";
    public static final String MAX_PROP = "jacorb.ssl.server_socket_factory.port.max";

    private ServerSocketFactory factory = null;

    private boolean require_mutual_auth = false;
    private boolean request_mutual_auth = false;
    private boolean trusteesFromKS = false;
    private String[] cipher_suites = null;
    private TrustManager trustManager = null;
    private short serverSupportedOptions = 0;
    private short serverRequiredOptions = 0;
    private String keystore_location = null;
    private String keystore_passphrase = null;
    private Logger logger;


    public PortRangeSSLServerSocketFactory(org.jacorb.orb.ORB orb)
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

        serverSupportedOptions = Short.parseShort(configuration.getAttribute("jacorb.security.ssl.server.supported_options", "20"), 16);

        serverRequiredOptions = Short.parseShort(configuration.getAttribute("jacorb.security.ssl.server.required_options", "0"), 16);

        if((serverSupportedOptions & 0x40) != 0)
        {
            // would prefer to establish trust in client.  If client can
            // support authentication, it will, otherwise we will continue
            if (logger.isInfoEnabled())
                logger.info("Will create SSL sockets that request client authentication");

            request_mutual_auth = true;
        }

        if((serverRequiredOptions & 0x40) != 0)
        {
            //required: establish trust in client
            //--> force other side to authenticate
            require_mutual_auth = true;
            request_mutual_auth = false;
            if (logger.isInfoEnabled())
                logger.info("Will create SSL sockets that require client authentication" );
        }

        keystore_location = configuration.getAttribute("jacorb.security.keystore", "UNSET");

        keystore_passphrase = configuration.getAttribute("jacorb.security.keystore_password", "UNSET");

        try
        {
            trustManager = (TrustManager)((org.jacorb.config.Configuration)configuration).getAttributeAsObject("jacorb.security.ssl.server.trust_manager");
        }
        catch (ConfigurationException ce)
        {
            if (logger.isErrorEnabled())
            {
                logger.error("TrustManager object creation failed. Please check value of property "
                        + "'jacorb.security.ssl.server.trust_manager'. Current value: " 
                        + configuration.getAttribute("jacorb.security.ssl.server.trust_manager", ""), ce); 
            }
        }

        try
        {
            factory = createServerSocketFactory();
        }
        catch(Exception e)
        {
            if (logger.isWarnEnabled())
                logger.warn("Exception", e );
        }

        if(factory == null)
        {
            if (logger.isErrorEnabled())
                logger.error("Unable to create PortRangeSSLServerSocketFactory!" );
            throw new ConfigurationException("Unable to create PortRangeSSLServerSocketFactory!");
        }


        // Andrew T. Finnell
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
                cipher_suites = new String [tokens];

                // This will fill the array in reverse order but that
                // doesn't matter
                while(tokenizer.hasMoreElements())
                {
                    cipher_suites[--tokens] = tokenizer.nextToken();
                }
            }
        }
    }


    @Override
    public ServerSocket createServerSocket(int port)
    throws IOException
    {
        if (port <= portMax && port >= portMin)
        {
            try
            {
                return doCreateServerSocket(port);
            }
            catch (IOException e)
            {
                // ignored
            }
        }
        
        for (int localPort = portMin; localPort <= portMax; localPort++)
        {
            try
            {
                return doCreateServerSocket(localPort);
            }
            catch (IOException ex)
            {
                // Ignore and continue
            }
        }

        return handleCreationFailed();
    }
    private ServerSocket doCreateServerSocket(int port)
    throws IOException
    {
        SSLServerSocket s = (SSLServerSocket)factory.createServerSocket(port);

        if (request_mutual_auth && ! require_mutual_auth) 
        {
            throw new RuntimeException("Request mutual authentication not supported with JSSE 1.0.x");
        }
        else if (require_mutual_auth) 
        {
            s.setNeedClientAuth(require_mutual_auth);
        }

        // Andrew T. Finnell / Change made for e-Security Inc. 2002 
        // We need a way to enable the cipher suites that we would
        // like to use. We should obtain these from the properties file.
        if( cipher_suites != null )
        {
            s.setEnabledCipherSuites(cipher_suites);    
        }

        if (logger.isDebugEnabled())
        {
            logger.debug("Created server socket at " + ":" + port);
        }
        return s;
    }


    @Override
    public ServerSocket createServerSocket(int port, int backlog) 
    throws IOException
    {
        if (port <= portMax && port >= portMin)
        {
            try
            {
                return doCreateServerSocket(port, backlog);
            }
            catch (IOException e)
            {
                // ignored 
            }
        }
        
        for (int localPort = portMin; localPort <= portMax; localPort++)
        {
            try
            {
                return doCreateServerSocket(localPort, backlog);
            }
            catch (IOException ex)
            {
                // Ignore and continue
            }
        }

        return handleCreationFailed();
    }
    private ServerSocket doCreateServerSocket(int port, int backlog) 
    throws IOException
    {
        SSLServerSocket s = (SSLServerSocket)factory.createServerSocket(port, backlog);

        if (request_mutual_auth && ! require_mutual_auth) 
        {
            throw new RuntimeException("Request mutual authentication not supported with JSSE 1.0.x");
        }
        else if (require_mutual_auth) 
        {
            s.setNeedClientAuth(require_mutual_auth);
        }

        // Andrew T. Finnell / Change made for e-Security Inc. 2002 
        // We need a way to enable the cipher suites that we would
        // like to use. We should obtain these from the properties file.
        if(cipher_suites != null)
        {
            s.setEnabledCipherSuites(cipher_suites);    
        }

        if (logger.isDebugEnabled())
        {
            logger.debug("PortRangeServerSocketFactory: Created server socket at " + ":" + port);
        }

        return s;
    }


    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress)
    throws IOException    
    {
        if (port <= portMax && port >= portMin)
        {
            try
            {
                return doCreateServerSocket(port, backlog, ifAddress);
            }
            catch (IOException e)
            {
                // ignore 
            }
        }
        
        for (int localPort = portMin; localPort <= portMax; localPort++)
        {
            try
            {
                return doCreateServerSocket(localPort, backlog, ifAddress);
            }
            catch (IOException ex)
            {
                // Ignore and continue
            }
        }

        return handleCreationFailed();
    }
    private ServerSocket doCreateServerSocket(int port, int backlog, InetAddress ifAddress) 
    throws IOException
    {
        SSLServerSocket s = (SSLServerSocket)factory.createServerSocket(port, backlog, ifAddress);

        if (request_mutual_auth && ! require_mutual_auth) 
        {
            throw new RuntimeException("Request mutual authentication not supported with JSSE 1.0.x");
        }
        else if (require_mutual_auth) 
        {
            s.setNeedClientAuth(require_mutual_auth);
        }

        // Andrew T. Finnell / Change made for e-Security Inc. 2002 
        // We need a way to enable the cipher suites that we would
        // like to use. We should obtain these from the properties file.
        if( cipher_suites != null )
        {
            s.setEnabledCipherSuites(cipher_suites);    
        }

        if (logger.isDebugEnabled())
        {
            logger.debug("Created server socket at " + ":" + port);
        }

        return s;
    }

    @Override
    public boolean isSSL(java.net.ServerSocket s)
    { 
        return (s instanceof SSLServerSocket); 
    }


    private ServerSocket handleCreationFailed()
    throws BindException
    {
        if (logger.isDebugEnabled())
        {
            logger.debug("Cannot create server socket between ports " + portMin + " and " + portMax);
        }

        throw new BindException ("PortRangeSSLServerSocketFactory: no free port between " + portMin + " and " + portMax);
    }


    private ServerSocketFactory createServerSocketFactory() 
    throws IOException, java.security.GeneralSecurityException
    {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());

        KeyStore key_store = KeyStoreUtil.getKeyStore(keystore_location, keystore_passphrase.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(key_store, keystore_passphrase.toCharArray());
        TrustManagerFactory tmf = null;

        //only add trusted certs, if establish trust in client
        //is required
        if(( serverRequiredOptions & 0x40) != 0 || ( serverSupportedOptions & 0x40) != 0) 
        {     
            tmf = TrustManagerFactory.getInstance("SunX509");

            if(trusteesFromKS)
            {
                tmf.init(key_store);
            }
            else
            {
                tmf.init((KeyStore)null);
            }
        }

        TrustManager[] trustManagers;

        if (trustManager == null)
        {
            trustManagers = (tmf == null)? null : tmf.getTrustManagers();
        }
        else
        {
            trustManagers = new TrustManager[] { trustManager };
            if (logger.isDebugEnabled())
            {
                logger.debug("Setting user specified server TrustManger : " + trustManager.getClass().toString());
            }
        }

        SSLContext ctx = SSLContext.getInstance( "TLS" );
        ctx.init(kmf.getKeyManagers(), trustManagers, null);

        return ctx.getServerSocketFactory();
    }
}

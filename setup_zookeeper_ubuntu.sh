#!/bin/bash

# This script installs and configures Apache Zookeeper, sets up TLS, SASL, 
# creates a dedicated user, and configures Zookeeper to run as a system service.

#==================================================================================================
#SET VARIABLES FOR FUTURE USE

# Set to true/false if you want to enable/disable SSL/SASL
SSL=true
SASL=true
zooport=2189
zooversion='3.9.2'

zoodata="/var/lib/zookeeper"
zoopath="/opt/zookeeper"
zoocfg="${zoopath}/conf/zoo.cfg"
zooserver="${zoopath}/bin/zkServer.sh"
zookeystore="${zoopath}/conf/keystore.jks"
zootruststore="${zoopath}/conf/truststore.jks"
zoojaas="${zoopath}/conf/jaas.conf"

password=$(openssl rand -base64 32)
if [ "$SSL" = true ]; then
    fullchain=$(sudo find /etc/letsencrypt/live/ -name fullchain.pem)
    privkey=$(sudo find /etc/letsencrypt/live/ -name privkey.pem)
    if [ -z "$fullchain" ] || [ -z "$privkey" ]; then
        echo "No SSL certificates found. Exiting."
        exit 1
    fi
fi

#==================================================================================================
# PRE-REQUISITES & WARNINGS

# Check if Java is installed
java --version || { echo "Java is not installed. https://www.oracle.com/java/technologies/downloads/ "; exit 1; }

if [ -d ${zoopath} ]; then
    echo "Zookeeper is already installed. Press any key to overwrite or CTRL+C to exit."
    read -n 1 -s
fi

#==================================================================================================
# DOWNLOAD AND INSTALL ZOOKEEPER

sudo wget https://downloads.apache.org/zookeeper/zookeeper-${zooversion}/apache-zookeeper-${zooversion}-bin.tar.gz
#quietly extract the tar file
sudo tar -xf apache-zookeeper-${zooversion}-bin.tar.gz 
sudo rsync -a --delete apache-zookeeper-${zooversion}-bin ${zoopath}
sudo rm -r apache-zookeeper-${zooversion}-bin.tar.gz apache-zookeeper-${zooversion}-bin
sudo mkdir -p ${zoodata}

#==================================================================================================
# CONFIGURE ZOOKEEPER

sudo tee ${zoocfg} > /dev/null << EOF
tickTime=2000
dataDir=${zoodata}
admin.enableServer=false
$(if [ "$SSL" != true ]; then printf "clientPort=${zooport}"; fi)
initLimit=5
syncLimit=2
maxClientCnxns=10

$(
if [ "$SSL" = true ]; then
printf "#TLS
secureClientPort=${zooport}
serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory
ssl.clientAuth=none
ssl.keyStore.location=${zookeystore}
ssl.keyStore.password=${password}
ssl.trustStore.location=${zootruststore}
ssl.trustStore.password=${password}"
fi
)

$(
if [ "$SASL" = true ]; then
printf "#SASL
allowSaslFailedClients=false
sessionRequireClientSASLAuth=true
java.security.auth.login.config=${zoojaas}
maintain_connection_despite_sasl_failure=false
authProvider.sasl=org.apache.zookeeper.server.auth.SASLAuthenticationProvider
requireClientAuthScheme=sasl
set.acl=true"
fi
)
EOF

#==================================================================================================
# SET ZOOKEEPER SASL AUTHENTICATION

if [ "$SASL" = true ]; then
sudo tee ${zoojaas} > /dev/null << EOF
Server {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_admin="$(openssl rand -base64 32)}";
};
EOF
fi

#==================================================================================================
# CREATE SSL CERTIFICATES AND KEYSTORES FROM LETSENCRYPT CERTIFICATES

if [ "$SSL" = true ]; then
    sudo rm -f ${zookeystore} ${zootruststore}
    sudo openssl pkcs12 -export -in ${fullchain} -inkey ${privkey} -out keystore.p12 -name zookeeper -password pass:${password}
    sudo keytool -importkeystore -deststorepass ${password} -destkeypass ${password} -destkeystore ${zookeystore} -srckeystore keystore.p12 -srcstoretype PKCS12 -srcstorepass ${password} -alias zookeeper
    sudo keytool -export -keystore ${zookeystore} -alias zookeeper -file zookeeper-cert.cer -storepass ${password}
    sudo keytool -import -trustcacerts -alias zookeeper -file zookeeper-cert.cer -keystore ${zootruststore} -storepass ${password} -noprompt
    sudo rm keystore.p12 zookeeper-cert.cer
fi

#==================================================================================================
#CREATE ZOOKEEPER USER AND SET PERMISSIONS

sudo useradd -s /bin/bash zookeeper || true
sudo usermod -aG sudo zookeeper
sudo chown -R zookeeper:zookeeper ${zoodata}
sudo chown -R zookeeper:zookeeper ${zoopath}

#==================================================================================================
# CONFIGURE ZOOKEEPER SYSTEMD SERVICE

sudo tee /etc/systemd/system/zookeeper.service > /dev/null << EOF
[Unit]
Description=Zookeeper Daemon
Documentation=http://zookeeper.apache.org
Requires=network.target
After=network.target

[Service]
Type=forking
WorkingDirectory=${zoopath}
User=zookeeper
Group=zookeeper
ExecStart=${zooserver} start ${zoocfg}
ExecStop=${zooserver} stop ${zoocfg}
ExecReload=${zooserver} restart ${zoocfg}
TimeoutSec=30
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Start and enable the Zookeeper service
sudo systemctl daemon-reload
sudo fuser -k ${zooport}/tcp || true
sudo systemctl start zookeeper
sudo systemctl enable zookeeper
sudo journalctl -u zookeeper -f

#==================================================================================================
# USE THE FOLLOWING CLIENT COMMANDS TO INTERACT WITH ZOOKEEPER
# zk = KazooClient(hosts='hostname:2189'); zk.start()                                                                    # No SSL, No SASL
# zk = KazooClient(hosts='hostname:2189', use_ssl=True); zk.start()                                                      # SSL, No SASL
# zk = KazooClient(hosts='hostname:2189', sasl_mechanism='DIGEST-MD5', username='admin', password='secret'); zk.start()  # SSL, SASL
FROM        ubuntu:trusty
MAINTAINER  MT

ENV         DEBIAN_FRONTEND noninteractive
ENV         HOME /home
WORKDIR     /home

RUN         useradd shinken

#
ADD         src/repo/sources.list /etc/apt/sources.list

#
RUN         apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3E5C1192 && \
            gpg --keyserver keys.gnupg.net --recv-keys F8C1CA08A57B9ED7 && \
            gpg --armor --export F8C1CA08A57B9ED7 | apt-key add - && \
            echo 'deb http://labs.consol.de/repo/stable/ubuntu trusty main' >> /etc/apt/sources.list && \
        
            apt-get update && \
            apt-get upgrade -y --no-install-recommends && \
            
            apt-get install -y --no-install-recommends build-essential \
            wget \
            supervisor \
            python-setuptools \
            python-pycurl \
            python-cherrypy3 \
            rrdtool \
            librrds-perl \
            php5-cli \
            php5-gd \
            libapache2-mod-php5 \
            apache2-utils \
            thruk \

            snmp \
            libnet-snmp-perl \
            libswitch-perl \
            liblist-compare-perl && \
            
            apt-get autoremove --purge -y && \
            apt-get autoclean -y && \
            apt-get clean -y
            

RUN         wget --no-check-certificate https://github.com/naparuba/shinken/archive/2.4.1.tar.gz && \
            wget --no-check-certificate https://github.com/lingej/pnp4nagios/archive/0.6.25.tar.gz && \
            wget --no-check-certificate https://www.monitoring-plugins.org/download/monitoring-plugins-2.1.1.tar.gz && \
            
            tar -xvzf 2.4.1.tar.gz && \
            tar -xvzf 0.6.25.tar.gz && \
            tar -xvzf monitoring-plugins-2.1.1.tar.gz && \

            cd shinken-2.4.1/ && \
            python ./setup.py install && \

            cd ../pnp4nagios-0.6.25 && \
            ./configure  --with-nagios-user=shinken  --with-nagios-group=shinken && \
            make all && \
            make fullinstall && \
            cp contrib/ssi/status-header.ssi /etc/thruk/ssi && \
            mv /usr/local/pnp4nagios/share/install.php /usr/local/pnp4nagios/share/install.php.bak && \

            cd ../monitoring-plugins-2.1.1 && \
            ./configure --with-cgiurl="/thruk/cgibin" && \
            make -j4 && \
            make install && \
            
            cd ../ && \
            rm -rf shinken-2.4.1 pnp4nagios-0.6.25 monitoring-plugins-2.1.1 && \
            rm -f 2.4.1.tar.gz 0.6.25.tar.gz monitoring-plugins-2.1.1.tar.gz && \
                    
            update-rc.d -f apache2 remove && \
            update-rc.d -f shinken remove && \
            a2enmod rewrite

RUN         shinken --init && \
            shinken install npcdmod && \
            shinken install logstore-sqlite && \
            shinken shinken install livestatus && \
            shinken shinken install simple-log

ADD         src/config/tools/check_fortigate_disk.bash        /usr/local/libexec/check_fortigate_disk.bash
ADD         src/config/tools/check_snmp_traffic.bash          /usr/local/libexec/check_snmp_traffic.bash
ADD         src/config/tools/check_fortigate.pl               /usr/local/libexec/check_fortigate.pl
ADD         src/config/tools/check_nwc_health.pl              /usr/local/libexec/check_nwc_health.pl 
ADD         src/config/tools/check_snmp_load.pl               /usr/local/libexec/check_snmp_load.pl       
ADD         src/config/tools/check_snmp_mem.pl                /usr/local/libexec/check_snmp_mem.pl        
ADD         src/config/tools/check_snmp_storage.pl            /usr/local/libexec/check_snmp_storage.pl
ADD         src/config/shinken/shinken.cfg                    /etc/shinken/shinken.cfg
ADD         src/config/shinken/broker-master.cfg              /etc/shinken/brokers/broker-master.cfg
ADD         src/config/shinken/livestatus.cfg                 /etc/shinken/modules/livestatus.cfg
ADD         src/config/shinken/reload-shinken.cfg             /etc/shinken/commands/reload-shinken.cfg
ADD         src/config/shinken/restart-shinken.cfg            /etc/shinken/commands/restart-shinken.cfg
ADD         src/config/thruk/thruk_local.conf                 /etc/thruk/thruk_local.conf
ADD         src/config/supervisor/conf.d                      /etc/supervisor/conf.d
ADD         src/config/apache2/apache2.conf                   /etc/apache2/apache2.conf
ADD         src/config/pnp4nagios/config_local.php            /usr/local/pnp4nagios/etc/config_local.php
ADD         src/config/shinken/paths.cfg                      /etc/shinken/resource.d/paths.cfg
ADD         src/config/pnp4nagios/pnp4nagios.conf             /etc/apache2/conf-available/pnp4nagios.conf
RUN         ln -s /etc/apache2/conf-available/pnp4nagios.conf /etc/apache2/conf-enabled/pnp4nagios.conf && \
            mkdir -p /etc/skconf
RUN         echo "www-data ALL=(ALL:ALL) NOPASSWD:/etc/init.d/shinken" >> /etc/sudoers

CMD         ["supervisord", "-c", "/etc/supervisor/supervisord.conf", "-n"]

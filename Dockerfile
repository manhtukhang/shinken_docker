FROM		ubuntu:trusty
MAINTAINER	MT

ENV 		DEBIAN_FRONTEND noninteractive
ENV			HOME /home

RUN			useradd shinken

WORKDIR 	/home

#
ADD 		src/repo/sources.list /etc/apt/sources.list

#
RUN			apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3E5C1192 && \
			gpg --keyserver keys.gnupg.net --recv-keys F8C1CA08A57B9ED7 && \
            gpg --armor --export F8C1CA08A57B9ED7 | apt-key add - && \
            echo 'deb http://labs.consol.de/repo/stable/ubuntu trusty main' >> /etc/apt/sources.list && \
		
			apt-get update && \
			apt-get upgrade -y && \
			
			apt-get install -y build-essential \
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
			thruk && \
			
			apt-get autoremove --purge -y && \
			apt-get autoclean -y && \
			apt-get clean -y
			

RUN			wget https://github.com/naparuba/shinken/archive/2.4.1.tar.gz && \
			wget https://github.com/lingej/pnp4nagios/archive/0.6.25.tar.gz && \
			tar -xvzf 2.4.1.tar.gz && \
			tar -xvzf 0.6.25.tar.gz && \

			cd shinken-2.4.1/ && \
			python ./setup.py install && \

			cd ../pnp4nagios-0.6.25 && \
			./configure  --with-nagios-user=shinken  --with-nagios-group=shinken && \
			make all && \
			make fullinstall && \
			cp contrib/ssi/status-header.ssi /etc/thruk/ssi && \
			mv /usr/local/pnp4nagios/share/install.php /usr/local/pnp4nagios/share/install.php.bak && \
			
			cd ../ && \
			rm -rf shinken-2.4.1 pnp4nagios-0.6.25 && \
			rm -f 2.4.1.tar.gz 0.6.25.tar.gz && \
					
			update-rc.d -f apache2 remove && \
			update-rc.d -f shinken remove && \
			a2enmod rewrite

RUN			shinken --init && \
            shinken install npcdmod && \
            shinken install logstore-sqlite && \
            shinken shinken install livestatus && \
            shinken shinken install simple-log
            
ADD         src/config/shinken/shinken.cfg /etc/shinken/shinken.cfg
ADD         src/config/shinken/broker-master.cfg /etc/shinken/brokers/broker-master.cfg
ADD			src/config/shinken/livestatus.cfg /etc/shinken/modules/livestatus.cfg
ADD			src/config/thruk/thruk_local.conf /etc/thruk/thruk_local.conf
ADD         src/config/supervisor/conf.d/* /etc/supervisor/conf.d/
ADD			src/config/pnp4nagios/config_local.php /usr/local/pnp4nagios/etc/config_local.php
ADD			src/config/pnp4nagios/pnp4nagios.conf /etc/apache2/conf-available/pnp4nagios.conf
RUN			ln -s /etc/apache2/conf-available/pnp4nagios.conf /etc/apache2/conf-enable/pnp4nagios.conf


#VOLUME		["/mnt", "/mnt"]

CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf", "-n"]


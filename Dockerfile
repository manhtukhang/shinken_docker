FROM		ubuntu:trusty
MAINTAINER	MT

ENV 		DEBIAN_FRONTEND noninteractive

RUN		useradd shinken --create-home

WORKDIR 	/home/shinken

#
ADD 		src/repo/sources.list /etc/apt/sources.list

#
RUN		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3E5C1192 && \
		gpg --keyserver keys.gnupg.net --recv-keys F8C1CA08A57B9ED7 && \
                gpg --armor --export F8C1CA08A57B9ED7 | apt-key add - && \
                echo 'deb http://labs.consol.de/repo/stable/ubuntu trusty main' >> /etc/apt/sources.list && \
		
		apt-get update && \
		apt-get upgrade -y && \
		
		apt-get install -y build-essential \
		wget \
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
		

RUN		wget https://github.com/naparuba/shinken/archive/2.4.1.tar.gz && \
		wget https://github.com/lingej/pnp4nagios/archive/0.6.25.tar.gz && \
		tar -xvzf 2.4.1.tar.gz && \
		tar -xvzf 0.6.25.tar.gz && \

		cd shinken-2.4.1/ && \
		python ./setup.py install && \

		cd ../pnp4nagios-0.6.25 && \
		./configure  --with-nagios-user=shinken  --with-nagios-group=shinken && \
		make all && \
		make fullinstall && \
		
		cd ../ && \
		rm -rf shinken-2.4.1 pnp4nagios-0.6.25 && \
		rm -f 2.4.1.tar.gz 0.6.25.tar.gz && \
				
		update-rc.d -f apache2 remove && \
		update-rc.d -f shinken remove && \

		chown -R shinken:shinken /etc/shinken/ && \
		sudo -u shinken shinken --init && \
#                su - shinken -c 'shinken install webui' && \
#               sudo -u shinken shinken install auth-htpasswd && \
                sudo -u shinken shinken install sqlitedb && \
#                su - shinken -c 'shinken install pickle-retention-file-scheduler' && \
#                su - shinken -c 'shinken install booster-nrpe' && \
                sudo -u shinken shinken install logstore-sqlite && \
                sudo -u shinken shinken install livestatus

#VOLUME		["/mnt", "/mnt"]


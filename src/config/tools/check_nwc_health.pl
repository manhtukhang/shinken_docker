#! /usr/bin/perl -w
# nagios: -epn

package Monitoring::GLPlugin;
use strict;
use IO::File;
use File::Basename;
use Digest::MD5 qw(md5_hex);
use Errno;
#use AutoLoader;
our $AUTOLOAD;

use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

{
  our $mode = undef;
  our $plugin = undef;
  our $pluginname = basename($ENV{'NAGIOS_PLUGIN'} || $0);
  our $blacklist = undef;
  our $info = [];
  our $extendedinfo = [];
  our $summary = [];
  our $variables = {};
}

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {};
  bless $self, $class;
  $Monitoring::GLPlugin::plugin = Monitoring::GLPlugin::Commandline->new(%params);
  return $self;
}

sub init {
  my $self = shift;
  if ($self->opts->can("blacklist") && $self->opts->blacklist &&
      -f $self->opts->blacklist) {
    $self->opts->blacklist = do {
        local (@ARGV, $/) = $self->opts->blacklist; <> };
  }
}

sub dumper {
  my $self = shift;
  my $object = shift;
  my $run = $object->{runtime};
  delete $object->{runtime};
  printf STDERR "%s\n", Data::Dumper::Dumper($object);
  $object->{runtime} = $run;
}

sub no_such_mode {
  my $self = shift;
  printf "Mode %s is not implemented for this type of device\n",
      $self->opts->mode;
  exit 3;
}

#########################################################
# framework-related. setup, options
#
sub add_default_args {
  my $self = shift;
  $self->add_arg(
      spec => 'mode=s',
      help => "--mode
   A keyword which tells the plugin what to do",
      required => 1,
  );
  $self->add_arg(
      spec => 'regexp',
      help => "--regexp
   if this parameter is used, name will be interpreted as a
   regular expression",
      required => 0,);
  $self->add_arg(
      spec => 'warning=s',
      help => "--warning
   The warning threshold",
      required => 0,);
  $self->add_arg(
      spec => 'critical=s',
      help => "--critical
   The critical threshold",
      required => 0,);
  $self->add_arg(
      spec => 'warningx=s%',
      help => '--warningx
   The extended warning thresholds
   e.g. --warningx db_msdb_free_pct=6: to override the threshold for a
   specific item ',
      required => 0,
  );
  $self->add_arg(
      spec => 'criticalx=s%',
      help => '--criticalx
   The extended critical thresholds',
      required => 0,
  );
  $self->add_arg(
      spec => 'units=s',
      help => "--units
   One of %, B, KB, MB, GB, Bit, KBi, MBi, GBi. (used for e.g. mode interface-usage)",
      required => 0,
  );
  $self->add_arg(
      spec => 'name=s',
      help => "--name
   The name of a specific component to check",
      required => 0,
  );
  $self->add_arg(
      spec => 'name2=s',
      help => "--name2
   The secondary name of a component",
      required => 0,
  );
  $self->add_arg(
      spec => 'blacklist|b=s',
      help => '--blacklist
   Blacklist some (missing/failed) components',
      required => 0,
      default => '',
  );
  $self->add_arg(
      spec => 'mitigation=s',
      help => "--mitigation
   The parameter allows you to change a critical error to a warning.",
      required => 0,
  );
  $self->add_arg(
      spec => 'lookback=s',
      help => "--lookback
   The amount of time you want to look back when calculating average rates.
   Use it for mode interface-errors or interface-usage. Without --lookback
   the time between two runs of check_nwc_health is the base for calculations.
   If you want your checkresult to be based for example on the past hour,
   use --lookback 3600. ",
      required => 0,
  );
  $self->add_arg(
      spec => 'environment|e=s%',
      help => "--environment
   Add a variable to the plugin's environment",
      required => 0,
  );
  $self->add_arg(
      spec => 'negate=s%',
      help => "--negate
   Emulate the negate plugin. --negate warning=critical --negate unknown=critical",
      required => 0,
  );
  $self->add_arg(
      spec => 'morphmessage=s%',
      help => '--morphmessage
   Modify the final output message',
      required => 0,
  );
  $self->add_arg(
      spec => 'morphperfdata=s%',
      help => "--morphperfdata
   The parameter allows you to change performance data labels.
   It's a perl regexp and a substitution.
   Example: --morphperfdata '(.*)ISATAP(.*)'='\$1patasi\$2'",
      required => 0,
  );
  $self->add_arg(
      spec => 'selectedperfdata=s',
      help => "--selectedperfdata
   The parameter allows you to limit the list of performance data. It's a perl regexp.
   Only matching perfdata show up in the output",
      required => 0,
  );
  $self->add_arg(
      spec => 'report=s',
      help => "--report
   Can be used to shorten the output",
      required => 0,
      default => 'long',
  );
  $self->add_arg(
      spec => 'multiline',
      help => '--multiline
   Multiline output',
      required => 0,
  );
  $self->add_arg(
      spec => 'with-mymodules-dyn-dir=s',
      help => "--with-mymodules-dyn-dir
   Add-on modules for the my-modes will be searched in this directory",
      required => 0,
  );
  $self->add_arg(
      spec => 'statefilesdir=s',
      help => '--statefilesdir
   An alternate directory where the plugin can save files',
      required => 0,
      env => 'STATEFILESDIR',
  );
  $self->add_arg(
      spec => 'isvalidtime=i',
      help => '--isvalidtime
   Signals the plugin to return OK if now is not a valid check time',
      required => 0,
      default => 1,
  );
  $self->add_arg(
      spec => 'reset',
      help => "--reset
   remove the state file",
      aliasfor => "name",
      required => 0,
      hidden => 1,
  );
  $self->add_arg(
      spec => 'drecksptkdb=s',
      help => "--drecksptkdb
   This parameter must be used instead of --name, because Devel::ptkdb is stealing the latter from the command line",
      aliasfor => "name",
      required => 0,
      hidden => 1,
  );
}

sub add_modes {
  my $self = shift;
  my $modes = shift;
  my $modestring = "";
  my @modes = @{$modes};
  my $longest = length ((reverse sort {length $a <=> length $b} map { $_->[1] } @modes)[0]);
  my $format = "       %-".
      (length ((reverse sort {length $a <=> length $b} map { $_->[1] } @modes)[0])).
      "s\t(%s)\n";
  foreach (@modes) {
    $modestring .= sprintf $format, $_->[1], $_->[3];
  }
  $modestring .= sprintf "\n";
  $Monitoring::GLPlugin::plugin->{modestring} = $modestring;
}

sub add_arg {
  my $self = shift;
  my %args = @_;
  if ($args{help} =~ /^--mode/) {
    $args{help} .= "\n".$Monitoring::GLPlugin::plugin->{modestring};
  }
  $Monitoring::GLPlugin::plugin->{opts}->add_arg(%args);
}

sub mod_arg {
  my $self = shift;
  $Monitoring::GLPlugin::plugin->{opts}->mod_arg(@_);
}

sub add_mode {
  my $self = shift;
  my %args = @_;
  push(@{$Monitoring::GLPlugin::plugin->{modes}}, \%args);
  my $longest = length ((reverse sort {length $a <=> length $b} map { $_->{spec} } @{$Monitoring::GLPlugin::plugin->{modes}})[0]);
  my $format = "       %-".
      (length ((reverse sort {length $a <=> length $b} map { $_->{spec} } @{$Monitoring::GLPlugin::plugin->{modes}})[0])).
      "s\t(%s)\n";
  $Monitoring::GLPlugin::plugin->{modestring} = "";
  foreach (@{$Monitoring::GLPlugin::plugin->{modes}}) {
    $Monitoring::GLPlugin::plugin->{modestring} .= sprintf $format, $_->{spec}, $_->{help};
  }
  $Monitoring::GLPlugin::plugin->{modestring} .= "\n";
}

sub validate_args {
  my $self = shift;
  if ($self->opts->mode =~ /^my-([^\-.]+)/) {
    my $param = $self->opts->mode;
    $param =~ s/\-/::/g;
    $self->add_mode(
        internal => $param,
        spec => $self->opts->mode,
        alias => undef,
        help => 'my extension',
    );
  } elsif ($self->opts->mode eq 'encode') {
    my $input = <>;
    chomp $input;
    $input =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;
    printf "%s\n", $input;
    exit 0;
  } elsif ((! grep { $self->opts->mode eq $_ } map { $_->{spec} } @{$Monitoring::GLPlugin::plugin->{modes}}) &&
      (! grep { $self->opts->mode eq $_ } map { defined $_->{alias} ? @{$_->{alias}} : () } @{$Monitoring::GLPlugin::plugin->{modes}})) {
    printf "UNKNOWN - mode %s\n", $self->opts->mode;
    $self->opts->print_help();
    exit 3;
  }
  if ($self->opts->name && $self->opts->name =~ /(%22)|(%27)/) {
    my $name = $self->opts->name;
    $name =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
    $self->override_opt('name', $name);
  }
  $Monitoring::GLPlugin::mode = (
      map { $_->{internal} }
      grep {
         ($self->opts->mode eq $_->{spec}) ||
         ( defined $_->{alias} && grep { $self->opts->mode eq $_ } @{$_->{alias}})
      } @{$Monitoring::GLPlugin::plugin->{modes}}
  )[0];
  if ($self->opts->multiline) {
    $ENV{NRPE_MULTILINESUPPORT} = 1;
  } else {
    $ENV{NRPE_MULTILINESUPPORT} = 0;
  }
  if ($self->opts->can("statefilesdir") && ! $self->opts->statefilesdir) {
    if ($^O =~ /MSWin/) {
      if (defined $ENV{TEMP}) {
        $self->override_opt('statefilesdir', $ENV{TEMP}."/".$Monitoring::GLPlugin::plugin->{name});
      } elsif (defined $ENV{TMP}) {
        $self->override_opt('statefilesdir', $ENV{TMP}."/".$Monitoring::GLPlugin::plugin->{name});
      } elsif (defined $ENV{windir}) {
        $self->override_opt('statefilesdir', File::Spec->catfile($ENV{windir}, 'Temp')."/".$Monitoring::GLPlugin::plugin->{name});
      } else {
        $self->override_opt('statefilesdir', "C:/".$Monitoring::GLPlugin::plugin->{name});
      }
    } elsif (exists $ENV{OMD_ROOT}) {
      $self->override_opt('statefilesdir', $ENV{OMD_ROOT}."/var/tmp/".$Monitoring::GLPlugin::plugin->{name});
    } else {
      $self->override_opt('statefilesdir', "/var/tmp/".$Monitoring::GLPlugin::plugin->{name});
    }
  }
  $Monitoring::GLPlugin::plugin->{statefilesdir} = $self->opts->statefilesdir 
      if $self->opts->can("statefilesdir");
  if ($self->opts->can("warningx") && $self->opts->warningx) {
    foreach my $key (keys %{$self->opts->warningx}) {
      $self->set_thresholds(metric => $key, 
          warning => $self->opts->warningx->{$key});
    }
  }
  if ($self->opts->can("criticalx") && $self->opts->criticalx) {
    foreach my $key (keys %{$self->opts->criticalx}) {
      $self->set_thresholds(metric => $key, 
          critical => $self->opts->criticalx->{$key});
    }
  }
  $self->set_timeout_alarm() if ! $SIG{'ALRM'};
}

sub set_timeout_alarm {
  my $self = shift;
  $SIG{'ALRM'} = sub {
    printf "UNKNOWN - %s timed out after %d seconds\n",
        $Monitoring::GLPlugin::plugin->{name}, $self->opts->timeout;
    exit 3;
  };
  alarm($self->opts->timeout);
}

#########################################################
# global helpers
#
sub set_variable {
  my $self = shift;
  my $key = shift;
  my $value = shift;
  $Monitoring::GLPlugin::variables->{$key} = $value;
}

sub get_variable {
  my $self = shift;
  my $key = shift;
  my $fallback = shift;
  return exists $Monitoring::GLPlugin::variables->{$key} ?
      $Monitoring::GLPlugin::variables->{$key} : $fallback;
}

sub debug {
  my $self = shift;
  my $format = shift;
  my $tracefile = "/tmp/".$Monitoring::GLPlugin::pluginname.".trace";
  $self->{trace} = -f $tracefile ? 1 : 0;
  if ($self->get_variable("verbose") &&
      $self->get_variable("verbose") > $self->get_variable("verbosity", 10)) {
    printf("%s: ", scalar localtime);
    printf($format, @_);
    printf "\n";
  }
  if ($self->{trace}) {
    my $logfh = new IO::File;
    $logfh->autoflush(1);
    if ($logfh->open($tracefile, "a")) {
      $logfh->printf("%s: ", scalar localtime);
      $logfh->printf($format, @_);
      $logfh->printf("\n");
      $logfh->close();
    }
  }
}

sub filter_namex {
  my $self = shift;
  my $opt = shift;
  my $name = shift;
  if ($opt) {
    if ($self->opts->regexp) {
      if ($name =~ /$opt/i) {
        return 1;
      }
    } else {
      if (lc $opt eq lc $name) {
        return 1;
      }
    }
  } else {
    return 1;
  }
  return 0;
}

sub filter_name {
  my $self = shift;
  my $name = shift;
  return $self->filter_namex($self->opts->name, $name);
}

sub filter_name2 {
  my $self = shift;
  my $name = shift;
  return $self->filter_namex($self->opts->name2, $name);
}

sub filter_name3 {
  my $self = shift;
  my $name = shift;
  return $self->filter_namex($self->opts->name3, $name);
}

sub version_is_minimum {
  my $self = shift;
  my $version = shift;
  my $installed_version;
  my $newer = 1;
  if ($self->get_variable("version")) {
    $installed_version = $self->get_variable("version");
  } elsif (exists $self->{version}) {
    $installed_version = $self->{version};
  } else {
    return 0;
  }
  my @v1 = map { $_ eq "x" ? 0 : $_ } split(/\./, $version);
  my @v2 = split(/\./, $installed_version);
  if (scalar(@v1) > scalar(@v2)) {
    push(@v2, (0) x (scalar(@v1) - scalar(@v2)));
  } elsif (scalar(@v2) > scalar(@v1)) {
    push(@v1, (0) x (scalar(@v2) - scalar(@v1)));
  }
  foreach my $pos (0..$#v1) {
    if ($v2[$pos] > $v1[$pos]) {
      $newer = 1;
      last;
    } elsif ($v2[$pos] < $v1[$pos]) {
      $newer = 0;
      last;
    }
  }
  return $newer;
}

sub accentfree {
  my $self = shift;
  my $text = shift;
  # thanks mycoyne who posted this accent-remove-algorithm
  # http://www.experts-exchange.com/Programming/Languages/Scripting/Perl/Q_23275533.html#a21234612
  my @transformed;
  my %replace = (
    '9a' => 's', '9c' => 'oe', '9e' => 'z', '9f' => 'Y', 'c0' => 'A', 'c1' => 'A',
    'c2' => 'A', 'c3' => 'A', 'c4' => 'A', 'c5' => 'A', 'c6' => 'AE', 'c7' => 'C',
    'c8' => 'E', 'c9' => 'E', 'ca' => 'E', 'cb' => 'E', 'cc' => 'I', 'cd' => 'I',
    'ce' => 'I', 'cf' => 'I', 'd0' => 'D', 'd1' => 'N', 'd2' => 'O', 'd3' => 'O',
    'd4' => 'O', 'd5' => 'O', 'd6' => 'O', 'd8' => 'O', 'd9' => 'U', 'da' => 'U',
    'db' => 'U', 'dc' => 'U', 'dd' => 'Y', 'e0' => 'a', 'e1' => 'a', 'e2' => 'a',
    'e3' => 'a', 'e4' => 'a', 'e5' => 'a', 'e6' => 'ae', 'e7' => 'c', 'e8' => 'e',
    'e9' => 'e', 'ea' => 'e', 'eb' => 'e', 'ec' => 'i', 'ed' => 'i', 'ee' => 'i',
    'ef' => 'i', 'f0' => 'o', 'f1' => 'n', 'f2' => 'o', 'f3' => 'o', 'f4' => 'o',
    'f5' => 'o', 'f6' => 'o', 'f8' => 'o', 'f9' => 'u', 'fa' => 'u', 'fb' => 'u',
    'fc' => 'u', 'fd' => 'y', 'ff' => 'y',
  );
  my @letters = split //, $text;;
  for (my $i = 0; $i <= $#letters; $i++) {
    my $hex = sprintf "%x", ord($letters[$i]);
    $letters[$i] = $replace{$hex} if (exists $replace{$hex});
  }
  push @transformed, @letters;
  return join '', @transformed;
}

sub dump {
  my $self = shift;
  my $class = ref($self);
  $class =~ s/^.*:://;
  if (exists $self->{flat_indices}) {
    printf "[%s_%s]\n", uc $class, $self->{flat_indices};
  } else {
    printf "[%s]\n", uc $class;
  }
  foreach (grep !/^(info|trace|warning|critical|blacklisted|extendedinfo|flat_indices|indices)/, sort keys %{$self}) {
    printf "%s: %s\n", $_, $self->{$_} if defined $self->{$_} && ref($self->{$_}) ne "ARRAY";
  }
  if ($self->{info}) {
    printf "info: %s\n", $self->{info};
  }
  printf "\n";
  foreach (grep !/^(info|trace|warning|critical|blacklisted|extendedinfo|flat_indices|indices)/, sort keys %{$self}) {
    if (defined $self->{$_} && ref($self->{$_}) eq "ARRAY") {
      my $have_flat_indices = 1;
      foreach my $obj (@{$self->{$_}}) {
        $have_flat_indices = 0 if (ref($obj) ne "HASH" || ! exists $obj->{flat_indices});
      }
      if ($have_flat_indices) {
        foreach my $obj (sort {
            join('', map { sprintf("%30d",$_) } split( /\./, $a->{flat_indices})) cmp
            join('', map { sprintf("%30d",$_) } split( /\./, $b->{flat_indices}))
        } @{$self->{$_}}) {
          $obj->dump();
        }
      } else {
        foreach my $obj (@{$self->{$_}}) {
          $obj->dump() if UNIVERSAL::can($obj, "isa") && $obj->can("dump");
        }
      }
    }
  }
}

sub table_ascii {
  my $self = shift;
  my $table = shift;
  my $titles = shift;
  my $text = "";
  my $column_length = {};
  my $column = 0;
  foreach (@{$titles}) {
    $column_length->{$column++} = length($_);
  }
  foreach my $tr (@{$table}) {
    @{$tr} = map { ref($_) eq "ARRAY" ? $_->[0] : $_; } @{$tr};
    $column = 0;
    foreach my $td (@{$tr}) {
      if (length($td) > $column_length->{$column}) {
        $column_length->{$column} = length($td);
      }
      $column++;
    }
  }
  $column = 0;
  foreach (@{$titles}) {
    $column_length->{$column} = "%".($column_length->{$column} + 3)."s";
    $column++;
  }
  $column = 0;
  foreach (@{$titles}) {
    $text .= sprintf $column_length->{$column++}, $_;
  }
  $text .= "\n";
  foreach my $tr (@{$table}) {
    $column = 0;
    foreach my $td (@{$tr}) {
      $text .= sprintf $column_length->{$column++}, $td;
    }
    $text .= "\n";
  }
  return $text;
}

sub table_html {
  my $self = shift;
  my $table = shift;
  my $titles = shift;
  my $text = "";
  $text .= "<table style=\"border-collapse:collapse; border: 1px solid black;\">";
  $text .= "<tr>";
  foreach (@{$titles}) {
    $text .= sprintf "<th style=\"text-align: left; padding-left: 4px; padding-right: 6px;\">%s</th>", $_;
  }
  $text .= "</tr>";
  foreach my $tr (@{$table}) {
    $text .= "<tr>";
    foreach my $td (@{$tr}) {
      my $class = "statusOK";
      if (ref($td) eq "ARRAY") {
        $class = {
          0 => "statusOK",
          1 => "statusWARNING",
          2 => "statusCRITICAL",
          3 => "statusUNKNOWN",
        }->{$td->[1]};
        $td = $td->[0];
      }
      $text .= sprintf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px;\" class=\"%s\">%s</td>", $class, $td;
    }
    $text .= "</tr>";
  }
  $text .= "</table>";
  return $text;
}

sub load_my_extension {
  my $self = shift;
  if ($self->opts->mode =~ /^my-([^-.]+)/) {
    my $class = $1;
    my $loaderror = undef;
    substr($class, 0, 1) = uc substr($class, 0, 1);
    if (! $self->opts->get("with-mymodules-dyn-dir")) {
      $self->override_opt("with-mymodules-dyn-dir", "");
    }
    my $plugin_name = $Monitoring::GLPlugin::pluginname;
    $plugin_name =~ /check_(.*?)_health/;
    $plugin_name = "Check".uc(substr($1, 0, 1)).substr($1, 1)."Health";
    foreach my $libpath (split(":", $self->opts->get("with-mymodules-dyn-dir"))) {
      foreach my $extmod (glob $libpath."/".$plugin_name."*.pm") {
        my $stderrvar;
        *SAVEERR = *STDERR;
        open OUT ,'>',\$stderrvar;
        *STDERR = *OUT;
        eval {
          $self->debug(sprintf "loading module %s", $extmod);
          require $extmod;
        };
        *STDERR = *SAVEERR;
        if ($@) {
          $loaderror = $extmod;
          $self->debug(sprintf "failed loading module %s: %s", $extmod, $@);
        }
      }
    }
    my $original_class = ref($self);
    my $original_init = $self->can("init");
    bless $self, "My$class";
    if ($self->isa("Monitoring::GLPlugin")) {
      my $new_init = $self->can("init");
      if ($new_init == $original_init) {
          $self->add_unknown(
              sprintf "Class %s needs an init() method", ref($self));
      } else {
        # now go back to check_*_health.pl where init() will be called
      }
    } else {
      bless $self, $original_class;
      $self->add_unknown(
          sprintf "Class %s is not a subclass of Monitoring::GLPlugin%s",
              "My$class",
              $loaderror ? sprintf " (syntax error in %s?)", $loaderror : "" );
      my ($code, $message) = $self->check_messages(join => ', ', join_all => ', ');
      $self->nagios_exit($code, $message);
    }
  }
}

sub decode_password {
  my $self = shift;
  my $password = shift;
  if ($password && $password =~ /^rfc3986:\/\/(.*)/) {
    $password =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
  }
  return $password;
}


#########################################################
# runtime methods
#
sub mode : lvalue {
  my $self = shift;
  $Monitoring::GLPlugin::mode;
}

sub statefilesdir {
  my $self = shift;
  return $Monitoring::GLPlugin::plugin->{statefilesdir};
}

sub opts { # die beiden _nicht_ in AUTOLOAD schieben, das kracht!
  my $self = shift;
  return $Monitoring::GLPlugin::plugin->opts();
}

sub getopts {
  my $self = shift;
  my $envparams = shift || [];
  $Monitoring::GLPlugin::plugin->getopts();
  # es kann sein, dass beim aufraeumen zum schluss als erstes objekt
  # das $Monitoring::GLPlugin::plugin geloescht wird. in anderen destruktoren
  # (insb. fuer dbi disconnect) steht dann $self->opts->verbose
  # nicht mehr zur verfuegung bzw. $Monitoring::GLPlugin::plugin->opts ist undef.
  $self->set_variable("verbose", $self->opts->verbose);
  #
  # die gueltigkeit von modes wird bereits hier geprueft und nicht danach
  # in validate_args. (zwischen getopts und validate_args wird
  # normalerweise classify aufgerufen, welches bereits eine verbindung
  # zum endgeraet herstellt. bei falschem mode waere das eine verschwendung
  # bzw. durch den exit3 ein evt. unsauberes beenden der verbindung.
  if ((! grep { $self->opts->mode eq $_ } map { $_->{spec} } @{$Monitoring::GLPlugin::plugin->{modes}}) &&
      (! grep { $self->opts->mode eq $_ } map { defined $_->{alias} ? @{$_->{alias}} : () } @{$Monitoring::GLPlugin::plugin->{modes}})) {
    if ($self->opts->mode !~ /^my-/) {
      printf "UNKNOWN - mode %s\n", $self->opts->mode;
      $self->opts->print_help();
      exit 3;
    }
  }
}

sub add_ok {
  my $self = shift;
  my $message = shift || $self->{info};
  $self->add_message(OK, $message);
}

sub add_warning {
  my $self = shift;
  my $message = shift || $self->{info};
  $self->add_message(WARNING, $message);
}

sub add_critical {
  my $self = shift;
  my $message = shift || $self->{info};
  $self->add_message(CRITICAL, $message);
}

sub add_unknown {
  my $self = shift;
  my $message = shift || $self->{info};
  $self->add_message(UNKNOWN, $message);
}

sub add_message {
  my $self = shift;
  my $level = shift;
  my $message = shift || $self->{info};
  $Monitoring::GLPlugin::plugin->add_message($level, $message)
      unless $self->is_blacklisted();
  if (exists $self->{failed}) {
    if ($level == UNKNOWN && $self->{failed} == OK) {
      $self->{failed} = $level;
    } elsif ($level > $self->{failed}) {
      $self->{failed} = $level;
    }
  }
}

sub clear_ok {
  my $self = shift;
  $self->clear_messages(OK);
}

sub clear_warning {
  my $self = shift;
  $self->clear_messages(WARNING);
}

sub clear_critical {
  my $self = shift;
  $self->clear_messages(CRITICAL);
}

sub clear_unknown {
  my $self = shift;
  $self->clear_messages(UNKNOWN);
}

sub clear_all { # deprecated, use clear_messages
  my $self = shift;
  $self->clear_ok();
  $self->clear_warning();
  $self->clear_critical();
  $self->clear_unknown();
}

sub set_level {
  my $self = shift;
  my $code = shift;
  $code = (qw(ok warning critical unknown))[$code] if $code =~ /^\d+$/;
  $code = lc $code;
  if (! exists $self->{tmp_level}) {
    $self->{tmp_level} = {
      ok => 0,
      warning => 0,
      critical => 0,
      unknown => 0,
    };
  }
  $self->{tmp_level}->{$code}++;
}

sub get_level {
  my $self = shift;
  return OK if ! exists $self->{tmp_level};
  my $code = OK;
  $code ||= CRITICAL if $self->{tmp_level}->{critical};
  $code ||= WARNING  if $self->{tmp_level}->{warning};
  $code ||= UNKNOWN  if $self->{tmp_level}->{unknown};
  return $code;
}

#########################################################
# blacklisting
#
sub blacklist {
  my $self = shift;
  $self->{blacklisted} = 1;
}

sub add_blacklist {
  my $self = shift;
  my $list = shift;
  $Monitoring::GLPlugin::blacklist = join('/',
      (split('/', $self->opts->blacklist), $list));
}

sub is_blacklisted {
  my $self = shift;
  if (! $self->opts->can("blacklist")) {
    return 0;
  }
  if (! exists $self->{blacklisted}) {
    $self->{blacklisted} = 0;
  }
  if (exists $self->{blacklisted} && $self->{blacklisted}) {
    return $self->{blacklisted};
  }
  # FAN:459,203/TEMP:102229/ENVSUBSYSTEM
  # FAN_459,FAN_203,TEMP_102229,ENVSUBSYSTEM
  if ($self->opts->blacklist =~ /_/) {
    foreach my $bl_item (split(/,/, $self->opts->blacklist)) {
      if ($bl_item eq $self->internal_name()) {
        $self->{blacklisted} = 1;
      }
    }
  } else {
    foreach my $bl_items (split(/\//, $self->opts->blacklist)) {
      if ($bl_items =~ /^(\w+):([\:\d\-,]+)$/) {
        my $bl_type = $1;
        my $bl_names = $2;
        foreach my $bl_name (split(/,/, $bl_names)) {
          if ($bl_type."_".$bl_name eq $self->internal_name()) {
            $self->{blacklisted} = 1;
          }
        }
      } elsif ($bl_items =~ /^(\w+)$/) {
        if ($bl_items eq $self->internal_name()) {
          $self->{blacklisted} = 1;
        }
      }
    }
  } 
  return $self->{blacklisted};
}

#########################################################
# additional info
#
sub add_info {
  my $self = shift;
  my $info = shift;
  $info = $self->is_blacklisted() ? $info.' (blacklisted)' : $info;
  $self->{info} = $info;
  push(@{$Monitoring::GLPlugin::info}, $info);
}

sub annotate_info {
  my $self = shift;
  my $annotation = shift;
  my $lastinfo = pop(@{$Monitoring::GLPlugin::info});
  $lastinfo .= sprintf ' (%s)', $annotation;
  $self->{info} = $lastinfo;
  push(@{$Monitoring::GLPlugin::info}, $lastinfo);
}

sub add_extendedinfo {  # deprecated
  my $self = shift;
  my $info = shift;
  $self->{extendedinfo} = $info;
  return if ! $self->opts->extendedinfo;
  push(@{$Monitoring::GLPlugin::extendedinfo}, $info);
}

sub get_info {
  my $self = shift;
  my $separator = shift || ' ';
  return join($separator , @{$Monitoring::GLPlugin::info});
}

sub get_last_info {
  my $self = shift;
  return pop(@{$Monitoring::GLPlugin::info});
}

sub get_extendedinfo {
  my $self = shift;
  my $separator = shift || ' ';
  return join($separator, @{$Monitoring::GLPlugin::extendedinfo});
}

sub add_summary {  # deprecated
  my $self = shift;
  my $summary = shift;
  push(@{$Monitoring::GLPlugin::summary}, $summary);
}

sub get_summary {
  my $self = shift;
  return join(', ', @{$Monitoring::GLPlugin::summary});
}

#########################################################
# persistency
#
sub valdiff {
  my $self = shift;
  my $pparams = shift;
  my %params = %{$pparams};
  my @keys = @_;
  my $now = time;
  my $newest_history_set = {};
  $params{freeze} = 0 if ! $params{freeze};
  my $mode = "normal";
  if ($self->opts->lookback && $self->opts->lookback == 99999 && $params{freeze} == 0) {
    $mode = "lookback_freeze_chill";
  } elsif ($self->opts->lookback && $self->opts->lookback == 99999 && $params{freeze} == 1) {
    $mode = "lookback_freeze_shockfrost";
  } elsif ($self->opts->lookback && $self->opts->lookback == 99999 && $params{freeze} == 2) {
    $mode = "lookback_freeze_defrost";
  } elsif ($self->opts->lookback) {
    $mode = "lookback";
  }
  # lookback=99999, freeze=0(default)
  #  nimm den letzten lauf und schreib ihn nach {cold}
  #  vergleich dann 
  #    wenn es frozen gibt, vergleich frozen und den letzten lauf
  #    sonst den letzten lauf und den aktuellen lauf
  # lookback=99999, freeze=1
  #  wird dann aufgerufen,wenn nach dem freeze=0 ein problem festgestellt wurde 
  #     (also als 2.valdiff hinterher)
  #  schreib cold nach frozen
  # lookback=99999, freeze=2
  #  wird dann aufgerufen,wenn nach dem freeze=0 wieder alles ok ist
  #     (also als 2.valdiff hinterher)
  #  loescht frozen
  #  
  my $last_values = $self->load_state(%params) || eval {
    my $empty_events = {};
    foreach (@keys) {
      if (ref($self->{$_}) eq "ARRAY") {
        $empty_events->{$_} = [];
      } else {
        $empty_events->{$_} = 0;
      }
    }
    $empty_events->{timestamp} = 0;
    if ($mode eq "lookback") {
      $empty_events->{lookback_history} = {};
    } elsif ($mode eq "lookback_freeze_chill") {
      $empty_events->{cold} = {};
      $empty_events->{frozen} = {};
    }
    $empty_events;
  };
  $self->{'delta_timestamp'} = $now - $last_values->{timestamp};
  foreach (@keys) {
    if ($mode eq "lookback_freeze_chill") {
      # die werte vom letzten lauf wegsichern.
      # vielleicht gibts gleich einen freeze=1, dann muessen die eingefroren werden
      if (exists $last_values->{$_}) {
        if (ref($self->{$_}) eq "ARRAY") {
          $last_values->{cold}->{$_} = [];
          foreach my $value (@{$last_values->{$_}}) {
            push(@{$last_values->{cold}->{$_}}, $value);
          }
        } else {
          $last_values->{cold}->{$_} = $last_values->{$_};
        }
      } else {
        if (ref($self->{$_}) eq "ARRAY") {
          $last_values->{cold}->{$_} = [];
        } else {
          $last_values->{cold}->{$_} = 0;
        }
      }
      # es wird so getan, als sei der frozen wert vom letzten lauf
      if (exists $last_values->{frozen}->{$_}) {
        if (ref($self->{$_}) eq "ARRAY") {
          $last_values->{$_} = [];
          foreach my $value (@{$last_values->{frozen}->{$_}}) {
            push(@{$last_values->{$_}}, $value);
          }
        } else {
          $last_values->{$_} = $last_values->{frozen}->{$_};
        }
      } 
    } elsif ($mode eq "lookback") {
      # find a last_value in the history which fits lookback best
      # and overwrite $last_values->{$_} with historic data
      if (exists $last_values->{lookback_history}->{$_}) {
        foreach my $date (sort {$a <=> $b} keys %{$last_values->{lookback_history}->{$_}}) {
            $newest_history_set->{$_} = $last_values->{lookback_history}->{$_}->{$date};
            $newest_history_set->{timestamp} = $date;
        }
        foreach my $date (sort {$a <=> $b} keys %{$last_values->{lookback_history}->{$_}}) {
          if ($date >= ($now - $self->opts->lookback)) {
            $last_values->{$_} = $last_values->{lookback_history}->{$_}->{$date};
            $last_values->{timestamp} = $date;
            last;
          } else {
            delete $last_values->{lookback_history}->{$_}->{$date};
          }
        }
      }
    }
    if ($mode eq "normal" || $mode eq "lookback" || $mode eq "lookback_freeze_chill") {
      if ($self->{$_} =~ /^\d+$/) {
        if ($self->opts->lookback) {
          $last_values->{$_} = 0 if ! exists $last_values->{$_};
          if ($self->{$_} >= $last_values->{$_}) {
            $self->{'delta_'.$_} = $self->{$_} - $last_values->{$_};
          } else {
            # vermutlich db restart und zaehler alle auf null
            $self->{'delta_'.$_} = $self->{$_};
          }
        }
        $self->debug(sprintf "delta_%s %f", $_, $self->{'delta_'.$_});
        $self->{$_.'_per_sec'} = $self->{'delta_timestamp'} ?
            $self->{'delta_'.$_} / $self->{'delta_timestamp'} : 0;
      } elsif (ref($self->{$_}) eq "ARRAY") {
        if ((! exists $last_values->{$_} || ! defined $last_values->{$_}) && exists $params{lastarray}) {
          # innerhalb der lookback-zeit wurde nichts in der lookback_history
          # gefunden. allenfalls irgendwas aelteres. normalerweise
          # wuerde jetzt das array als [] initialisiert.
          # d.h. es wuerde ein delta geben, @found s.u.
          # wenn man das nicht will, sondern einfach aktuelles array mit
          # dem array des letzten laufs vergleichen will, setzt man lastarray
          $last_values->{$_} = %{$newest_history_set} ?
              $newest_history_set->{$_} : []
        } elsif ((! exists $last_values->{$_} || ! defined $last_values->{$_}) && ! exists $params{lastarray}) {
          $last_values->{$_} = [] if ! exists $last_values->{$_};
        } elsif (exists $last_values->{$_} && ! defined $last_values->{$_}) {
          # $_ kann es auch ausserhalb des lookback_history-keys als normalen
          # key geben. der zeigt normalerweise auf den entspr. letzten
          # lookback_history eintrag. wurde der wegen ueberalterung abgeschnitten
          # ist der hier auch undef.
          $last_values->{$_} = %{$newest_history_set} ?
              $newest_history_set->{$_} : []
        }
        my %saved = map { $_ => 1 } @{$last_values->{$_}};
        my %current = map { $_ => 1 } @{$self->{$_}};
        my @found = grep(!defined $saved{$_}, @{$self->{$_}});
        my @lost = grep(!defined $current{$_}, @{$last_values->{$_}});
        $self->{'delta_found_'.$_} = \@found;
        $self->{'delta_lost_'.$_} = \@lost;
      }
    }
  }
  $params{save} = eval {
    my $empty_events = {};
    foreach (@keys) {
      $empty_events->{$_} = $self->{$_};
      if ($mode =~ /lookback_freeze/) {
        if (exists $last_values->{frozen}->{$_}) {
          $empty_events->{cold}->{$_} = $last_values->{frozen}->{$_};
        } else {
          $empty_events->{cold}->{$_} = $last_values->{cold}->{$_};
        }
        $empty_events->{cold}->{timestamp} = $last_values->{cold}->{timestamp};
      }
      if ($mode eq "lookback_freeze_shockfrost") {
        $empty_events->{frozen}->{$_} = $empty_events->{cold}->{$_};
        $empty_events->{frozen}->{timestamp} = $now;
      }
    }
    $empty_events->{timestamp} = $now;
    if ($mode eq "lookback") {
      $empty_events->{lookback_history} = $last_values->{lookback_history};
      foreach (@keys) {
        $empty_events->{lookback_history}->{$_}->{$now} = $self->{$_};
      }
    }
    if ($mode eq "lookback_freeze_defrost") {
      delete $empty_events->{freeze};
    }
    $empty_events;
  };
  $self->save_state(%params);
}

sub create_statefilesdir {
  my $self = shift;
  if (! -d $self->statefilesdir()) {
    eval {
      use File::Path;
      mkpath $self->statefilesdir();
    };
    if ($@ || ! -w $self->statefilesdir()) {
      $self->add_message(UNKNOWN,
        sprintf "cannot create status dir %s! check your filesystem (permissions/usage/integrity) and disk devices", $self->statefilesdir());
    }
  } elsif (! -w $self->statefilesdir()) {
    $self->add_message(UNKNOWN,
        sprintf "cannot write status dir %s! check your filesystem (permissions/usage/integrity) and disk devices", $self->statefilesdir());
  }
}

sub create_statefile {
  my $self = shift;
  my %params = @_;
  my $extension = "";
  $extension .= $params{name} ? '_'.$params{name} : '';
  $extension =~ s/\//_/g;
  $extension =~ s/\(/_/g;
  $extension =~ s/\)/_/g;
  $extension =~ s/\*/_/g;
  $extension =~ s/\s/_/g;
  return sprintf "%s/%s%s", $self->statefilesdir(),
      $self->opts->mode, lc $extension;
}

sub schimpf {
  my $self = shift;
  printf "statefilesdir %s is not writable.\nYou didn't run this plugin as root, didn't you?\n", $self->statefilesdir();
}

# $self->protect_value('1.1-flat_index', 'cpu_busy', 'percent');
sub protect_value {
  my $self = shift;
  my $ident = shift;
  my $key = shift;
  my $validfunc = shift;
  if (ref($validfunc) ne "CODE" && $validfunc eq "percent") {
    $validfunc = sub {
      my $value = shift;
      return 0 if $value !~ /^[-+]?([0-9]+(\.[0-9]+)?|\.[0-9]+)$/;
      return ($value < 0 || $value > 100) ? 0 : 1;
    };
  } elsif (ref($validfunc) ne "CODE" && $validfunc eq "positive") {
    $validfunc = sub {
      my $value = shift;
      return 0 if $value !~ /^[-+]?([0-9]+(\.[0-9]+)?|\.[0-9]+)$/;
      return ($value < 0) ? 0 : 1;
    };
  }
  if (&$validfunc($self->{$key})) {
    $self->save_state(name => 'protect_'.$ident.'_'.$key, save => {
        $key => $self->{$key},
        exception => 0,
    });
  } else {
    # if the device gives us an clearly wrong value, simply use the last value.
    my $laststate = $self->load_state(name => 'protect_'.$ident.'_'.$key);
    $self->debug(sprintf "self->{%s} is %s and invalid for the %dth time",
        $key, $self->{$key}, $laststate->{exception} + 1);
    if ($laststate->{exception} <= 5) {
      # but only 5 times.
      # if the error persists, somebody has to check the device.
      $self->{$key} = $laststate->{$key};
    }
    $self->save_state(name => 'protect_'.$ident.'_'.$key, save => {
        $key => $laststate->{$key},
        exception => $laststate->{exception}++,
    });
  }
}

sub save_state {
  my $self = shift;
  my %params = @_;
  $self->create_statefilesdir();
  my $statefile = $self->create_statefile(%params);
  my $tmpfile = $self->statefilesdir().'/check__health_tmp_'.$$;
  if ((ref($params{save}) eq "HASH") && exists $params{save}->{timestamp}) {
    $params{save}->{localtime} = scalar localtime $params{save}->{timestamp};
  }
  my $seekfh = new IO::File;
  if ($seekfh->open($tmpfile, "w")) {
    $seekfh->printf("%s", Data::Dumper::Dumper($params{save}));
    $seekfh->flush();
    $seekfh->close();
    $self->debug(sprintf "saved %s to %s",
        Data::Dumper::Dumper($params{save}), $statefile);
  }
  if (! rename $tmpfile, $statefile) {
    $self->add_message(UNKNOWN,
        sprintf "cannot write status file %s! check your filesystem (permissions/usage/integrity) and disk devices", $statefile);
  }
}

sub load_state {
  my $self = shift;
  my %params = @_;
  my $statefile = $self->create_statefile(%params);
  if ( -f $statefile) {
    our $VAR1;
    eval {
      require $statefile;
    };
    if($@) {
      printf "rumms\n";
    }
    $self->debug(sprintf "load %s", Data::Dumper::Dumper($VAR1));
    return $VAR1;
  } else {
    return undef;
  }
}

#########################################################
# daemon mode
#
sub check_pidfile {
  my $self = shift;
  my $fh = new IO::File;
  if ($fh->open($self->{pidfile}, "r")) {
    my $pid = $fh->getline();
    $fh->close();
    if (! $pid) {
      $self->debug("Found pidfile %s with no valid pid. Exiting.",
          $self->{pidfile});
      return 0;
    } else {
      $self->debug("Found pidfile %s with pid %d", $self->{pidfile}, $pid);
      kill 0, $pid;
      if ($! == Errno::ESRCH) {
        $self->debug("This pidfile is stale. Writing a new one");
        $self->write_pidfile();
        return 1;
      } else {
        $self->debug("This pidfile is held by a running process. Exiting");
        return 0;
      }
    }
  } else {
    $self->debug("Found no pidfile. Writing a new one");
    $self->write_pidfile();
    return 1;
  }
}

sub write_pidfile {
  my $self = shift;
  if (! -d dirname($self->{pidfile})) {
    eval "require File::Path;";
    if (defined(&File::Path::mkpath)) {
      import File::Path;
      eval { mkpath(dirname($self->{pidfile})); };
    } else {
      my @dirs = ();
      map {
          push @dirs, $_;
          mkdir(join('/', @dirs))
              if join('/', @dirs) && ! -d join('/', @dirs);
      } split(/\//, dirname($self->{pidfile}));
    }
  }
  my $fh = new IO::File;
  $fh->autoflush(1);
  if ($fh->open($self->{pidfile}, "w")) {
    $fh->printf("%s", $$);
    $fh->close();
  } else {
    $self->debug("Could not write pidfile %s", $self->{pidfile});
    die "pid file could not be written";
  }
}

sub AUTOLOAD {
  my $self = shift;
  return if ($AUTOLOAD =~ /DESTROY/);
  $self->debug("AUTOLOAD %s\n", $AUTOLOAD)
        if $self->opts->verbose >= 2;
  if ($AUTOLOAD =~ /^(.*)::analyze_and_check_(.*)_subsystem$/) {
    my $class = $1;
    my $subsystem = $2;
    my $analyze = sprintf "analyze_%s_subsystem", $subsystem;
    my $check = sprintf "check_%s_subsystem", $subsystem;
    my @params = @_;
    if (@params) {
      # analyzer class
      my $subsystem_class = shift @params;
      $self->{components}->{$subsystem.'_subsystem'} = $subsystem_class->new();
      $self->debug(sprintf "\$self->{components}->{%s_subsystem} = %s->new()",
          $subsystem, $subsystem_class);
    } else {
      $self->$analyze();
      $self->debug("call %s()", $analyze);
    }
    $self->$check();
  } elsif ($AUTOLOAD =~ /^(.*)::check_(.*)_subsystem$/) {
    my $class = $1;
    my $subsystem = sprintf "%s_subsystem", $2;
    $self->{components}->{$subsystem}->check();
    $self->{components}->{$subsystem}->dump()
        if $self->opts->verbose >= 2;
  } elsif ($AUTOLOAD =~ /^.*::(status_code|check_messages|nagios_exit|html_string|perfdata_string|selected_perfdata|check_thresholds|get_thresholds|opts)$/) {
    return $Monitoring::GLPlugin::plugin->$1(@_);
  } elsif ($AUTOLOAD =~ /^.*::(clear_messages|suppress_messages|add_html|add_perfdata|override_opt|create_opt|set_thresholds|force_thresholds)$/) {
    $Monitoring::GLPlugin::plugin->$1(@_);
  } elsif ($AUTOLOAD =~ /^.*::mod_arg_(.*)$/) {
    return $Monitoring::GLPlugin::plugin->mod_arg($1, @_);
  } else {
    $self->debug("AUTOLOAD: class %s has no method %s\n",
        ref($self), $AUTOLOAD);
  }
}


package Monitoring::GLPlugin::Commandline;
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3, DEPENDENT => 4 };
our %ERRORS = (
    'OK'        => OK,
    'WARNING'   => WARNING,
    'CRITICAL'  => CRITICAL,
    'UNKNOWN'   => UNKNOWN,
    'DEPENDENT' => DEPENDENT,
);

our %STATUS_TEXT = reverse %ERRORS;


sub new {
  my $class = shift;
  my %params = @_;
  my $self = {
       perfdata => [],
       messages => {
         ok => [],
         warning => [],
         critical => [],
         unknown => [],
       },
       args => [],
       opts => Monitoring::GLPlugin::Commandline::Getopt->new(%params),
       modes => [],
       statefilesdir => undef,
  };
  foreach (qw(shortname usage version url plugin blurb extra
      license timeout)) {
    $self->{$_} = $params{$_};
  }
  bless $self, $class;
  $self->{name} = $self->{plugin};
  $Monitoring::GLPlugin::plugin = $self;
}

sub AUTOLOAD {
  my $self = shift;
  return if ($AUTOLOAD =~ /DESTROY/);
  $self->debug("AUTOLOAD %s\n", $AUTOLOAD)
        if $self->{opts}->verbose >= 2;
  if ($AUTOLOAD =~ /^.*::(add_arg|override_opt|create_opt)$/) {
    $self->{opts}->$1(@_);
  }
}

sub DESTROY {
  my $self = shift;
  # ohne dieses DESTROY rennt nagios_exit in obiges AUTOLOAD rein
  # und fliegt aufs Maul, weil {opts} bereits nicht mehr existiert.
  # Unerklaerliches Verhalten.
}

sub debug {
  my $self = shift;
  my $format = shift;
  my $tracefile = "/tmp/".$Monitoring::GLPlugin::pluginname.".trace";
  $self->{trace} = -f $tracefile ? 1 : 0;
  if ($self->opts->verbose && $self->opts->verbose > 10) {
    printf("%s: ", scalar localtime);
    printf($format, @_);
    printf "\n";
  }
  if ($self->{trace}) {
    my $logfh = new IO::File;
    $logfh->autoflush(1);
    if ($logfh->open($tracefile, "a")) {
      $logfh->printf("%s: ", scalar localtime);
      $logfh->printf($format, @_);
      $logfh->printf("\n");
      $logfh->close();
    }
  }
}

sub opts {
  my $self = shift;
  return $self->{opts};
}

sub getopts {
  my $self = shift;
  $self->opts->getopts();
}

sub add_message {
  my $self = shift;
  my ($code, @messages) = @_;
  $code = (qw(ok warning critical unknown))[$code] if $code =~ /^\d+$/;
  $code = lc $code;
  push @{$self->{messages}->{$code}}, @messages;
}

sub selected_perfdata {
  my $self = shift;
  my $label = shift;
  if ($self->opts->can("selectedperfdata") && $self->opts->selectedperfdata) {
    my $pattern = $self->opts->selectedperfdata;
    return ($label =~ /$pattern/i) ? 1 : 0;
  } else {
    return 1;
  }
}

sub add_perfdata {
  my ($self, %args) = @_;
#printf "add_perfdata %s\n", Data::Dumper::Dumper(\%args);
#printf "add_perfdata %s\n", Data::Dumper::Dumper($self->{thresholds});
#
# wenn warning, critical, dann wird von oben ein expliziter wert mitgegeben
# wenn thresholds
#  wenn label in 
#    warningx $self->{thresholds}->{$label}->{warning} existiert
#  dann nimm $self->{thresholds}->{$label}->{warning}
#  ansonsten thresholds->default->warning
#

  my $label = $args{label};
  my $value = $args{value};
  my $uom = $args{uom} || "";
  my $format = '%d';

  if ($self->opts->can("morphperfdata") && $self->opts->morphperfdata) {
    # 'Intel [R] Interface (\d+) usage'='nic$1'
    foreach my $key (keys %{$self->opts->morphperfdata}) {
      if ($label =~ /$key/) {
        my $replacement = '"'.$self->opts->morphperfdata->{$key}.'"';
        my $oldlabel = $label;
        $label =~ s/$key/$replacement/ee;
        if (exists $self->{thresholds}->{$oldlabel}) {
          %{$self->{thresholds}->{$label}} = %{$self->{thresholds}->{$oldlabel}};
        }
      }
    }
  }
  if ($value =~ /\./) {
    if (defined $args{places}) {
      $value = sprintf '%.'.$args{places}.'f', $value;
    } else {
      $value = sprintf "%.2f", $value;
    }
  } else {
    $value = sprintf "%d", $value;
  }
  my $warn = "";
  my $crit = "";
  my $min = defined $args{min} ? $args{min} : "";
  my $max = defined $args{max} ? $args{max} : "";
  if ($args{thresholds} || (! exists $args{warning} && ! exists $args{critical})) {
    if (exists $self->{thresholds}->{$label}->{warning}) {
      $warn = $self->{thresholds}->{$label}->{warning};
    } elsif (exists $self->{thresholds}->{default}->{warning}) {
      $warn = $self->{thresholds}->{default}->{warning};
    }
    if (exists $self->{thresholds}->{$label}->{critical}) {
      $crit = $self->{thresholds}->{$label}->{critical};
    } elsif (exists $self->{thresholds}->{default}->{critical}) {
      $crit = $self->{thresholds}->{default}->{critical};
    }
  } else {
    if ($args{warning}) {
      $warn = $args{warning};
    }
    if ($args{critical}) {
      $crit = $args{critical};
    }
  }
  if ($uom eq "%") {
    $min = 0;
    $max = 100;
  }
  if (defined $args{places}) {
    # cut off excessive decimals which may be the result of a division
    # length = places*2, no trailing zeroes
    if ($warn ne "") {
      $warn = join("", map {
          s/\.0+$//; $_
      } map {
          s/(\.[1-9]+)0+$/$1/; $_
      } map {
          /[\+\-\d\.]+/ ? sprintf '%.'.2*$args{places}.'f', $_ : $_;
      } split(/([\+\-\d\.]+)/, $warn));
    }
    if ($crit ne "") {
      $crit = join("", map {
          s/\.0+$//; $_
      } map {
          s/(\.[1-9]+)0+$/$1/; $_
      } map {
          /[\+\-\d\.]+/ ? sprintf '%.'.2*$args{places}.'f', $_ : $_;
      } split(/([\+\-\d\.]+)/, $crit));
    }
    if ($min ne "") {
      $min = join("", map {
          s/\.0+$//; $_
      } map {
          s/(\.[1-9]+)0+$/$1/; $_
      } map {
          /[\+\-\d\.]+/ ? sprintf '%.'.2*$args{places}.'f', $_ : $_;
      } split(/([\+\-\d\.]+)/, $min));
    }
    if ($max ne "") {
      $max = join("", map {
          s/\.0+$//; $_
      } map {
          s/(\.[1-9]+)0+$/$1/; $_
      } map {
          /[\+\-\d\.]+/ ? sprintf '%.'.2*$args{places}.'f', $_ : $_;
      } split(/([\+\-\d\.]+)/, $max));
    }
  }
  push @{$self->{perfdata}}, sprintf("'%s'=%s%s;%s;%s;%s;%s",
      $label, $value, $uom, $warn, $crit, $min, $max)
      if $self->selected_perfdata($label);
}

sub add_html {
  my $self = shift;
  my $line = shift;
  push @{$self->{html}}, $line;
}

sub suppress_messages {
  my $self = shift;
  $self->{suppress_messages} = 1;
}

sub clear_messages {
  my $self = shift;
  my $code = shift;
  $code = (qw(ok warning critical unknown))[$code] if $code =~ /^\d+$/;
  $code = lc $code;
  $self->{messages}->{$code} = [];
}

sub check_messages {
  my $self = shift;
  my %args = @_;

  # Add object messages to any passed in as args
  for my $code (qw(critical warning unknown ok)) {
    my $messages = $self->{messages}->{$code} || [];
    if ($args{$code}) {
      unless (ref $args{$code} eq 'ARRAY') {
        if ($code eq 'ok') {
          $args{$code} = [ $args{$code} ];
        }
      }
      push @{$args{$code}}, @$messages;
    } else {
      $args{$code} = $messages;
    }
  }
  my %arg = %args;
  $arg{join} = ' ' unless defined $arg{join};

  # Decide $code
  my $code = OK;
  $code ||= CRITICAL  if @{$arg{critical}};
  $code ||= WARNING   if @{$arg{warning}};
  $code ||= UNKNOWN   if @{$arg{unknown}};
  return $code unless wantarray;

  # Compose message
  my $message = '';
  if ($arg{join_all}) {
      $message = join( $arg{join_all},
          map { @$_ ? join( $arg{'join'}, @$_) : () }
              $arg{critical},
              $arg{warning},
              $arg{unknown},
              $arg{ok} ? (ref $arg{ok} ? $arg{ok} : [ $arg{ok} ]) : []
      );
  }

  else {
      $message ||= join( $arg{'join'}, @{$arg{critical}} )
          if $code == CRITICAL;
      $message ||= join( $arg{'join'}, @{$arg{warning}} )
          if $code == WARNING;
      $message ||= join( $arg{'join'}, @{$arg{unknown}} )
          if $code == UNKNOWN;
      $message ||= ref $arg{ok} ? join( $arg{'join'}, @{$arg{ok}} ) : $arg{ok}
          if $arg{ok};
  }

  return ($code, $message);
}

sub status_code {
  my $self = shift;
  my $code = shift;
  $code = (qw(ok warning critical unknown))[$code] if $code =~ /^\d+$/;
  $code = uc $code;
  $code = $ERRORS{$code} if defined $code && exists $ERRORS{$code};
  $code = UNKNOWN unless defined $code && exists $STATUS_TEXT{$code};
  return "$STATUS_TEXT{$code}";
}

sub perfdata_string {
  my $self = shift;
  if (scalar (@{$self->{perfdata}})) {
    return join(" ", @{$self->{perfdata}});
  } else {
    return "";
  }
}

sub html_string {
  my $self = shift;
  if (scalar (@{$self->{html}})) {
    return join(" ", @{$self->{html}});
  } else {
    return "";
  }
}

sub nagios_exit {
  my $self = shift;
  my ($code, $message, $arg) = @_;
  $code = $ERRORS{$code} if defined $code && exists $ERRORS{$code};
  $code = UNKNOWN unless defined $code && exists $STATUS_TEXT{$code};
  $message = '' unless defined $message;
  if (ref $message && ref $message eq 'ARRAY') {
      $message = join(' ', map { chomp; $_ } @$message);
  } else {
      chomp $message;
  }
  if ($self->opts->negate) {
    my $original_code = $code;
    foreach my $from (keys %{$self->opts->negate}) {
      if ((uc $from) =~ /^(OK|WARNING|CRITICAL|UNKNOWN)$/ &&
          (uc $self->opts->negate->{$from}) =~ /^(OK|WARNING|CRITICAL|UNKNOWN)$/) {
        if ($original_code == $ERRORS{uc $from}) {
          $code = $ERRORS{uc $self->opts->negate->{$from}};
        }
      }
    }
  }
  my $output = "$STATUS_TEXT{$code}";
  $output .= " - $message" if defined $message && $message ne '';
  if ($self->opts->can("morphmessage") && $self->opts->morphmessage) {
    # 'Intel [R] Interface (\d+) usage'='nic$1'
    # '^OK.*'="alles klar"   '^CRITICAL.*'="alles hi"
    foreach my $key (keys %{$self->opts->morphmessage}) {
      if ($output =~ /$key/) {
        my $replacement = '"'.$self->opts->morphmessage->{$key}.'"';
        $output =~ s/$key/$replacement/ee;
      }
    }
  }
  if (scalar (@{$self->{perfdata}})) {
    $output .= " | ".$self->perfdata_string();
  }
  $output .= "\n";
  if ($self->opts->can("isvalidtime") && ! $self->opts->isvalidtime) {
    $code = OK;
    $output = "OK - outside valid timerange. check results are not relevant now. original message was: ".
        $output;
  }
  if (! exists $self->{suppress_messages}) {
    print $output;
  }
  exit $code;
}

sub set_thresholds {
  my $self = shift;
  my %params = @_;
  if (exists $params{metric}) {
    my $metric = $params{metric};
    # erst die hartcodierten defaultschwellwerte
    $self->{thresholds}->{$metric}->{warning} = $params{warning};
    $self->{thresholds}->{$metric}->{critical} = $params{critical};
    # dann die defaultschwellwerte von der kommandozeile
    if (defined $self->opts->warning) {
      $self->{thresholds}->{$metric}->{warning} = $self->opts->warning;
    }
    if (defined $self->opts->critical) {
      $self->{thresholds}->{$metric}->{critical} = $self->opts->critical;
    }
    # dann die ganz spezifischen schwellwerte von der kommandozeile
    if ($self->opts->warningx) { # muss nicht auf defined geprueft werden, weils ein hash ist
      foreach my $key (keys %{$self->opts->warningx}) {
        next if $key ne $metric;
        $self->{thresholds}->{$metric}->{warning} = $self->opts->warningx->{$key};
      }
    }
    if ($self->opts->criticalx) {
      foreach my $key (keys %{$self->opts->criticalx}) {
        next if $key ne $metric;
        $self->{thresholds}->{$metric}->{critical} = $self->opts->criticalx->{$key};
      }
    }
  } else {
    $self->{thresholds}->{default}->{warning} =
        defined $self->opts->warning ? $self->opts->warning : defined $params{warning} ? $params{warning} : 0;
    $self->{thresholds}->{default}->{critical} =
        defined $self->opts->critical ? $self->opts->critical : defined $params{critical} ? $params{critical} : 0;
  }
}

sub force_thresholds {
  my $self = shift;
  my %params = @_;
  if (exists $params{metric}) {
    my $metric = $params{metric};
    $self->{thresholds}->{$metric}->{warning} = $params{warning} || 0;
    $self->{thresholds}->{$metric}->{critical} = $params{critical} || 0;
  } else {
    $self->{thresholds}->{default}->{warning} = $params{warning} || 0;
    $self->{thresholds}->{default}->{critical} = $params{critical} || 0;
  }
}

sub get_thresholds {
  my $self = shift;
  my @params = @_;
  if (scalar(@params) > 1) {
    my %params = @params;
    my $metric = $params{metric};
    return ($self->{thresholds}->{$metric}->{warning},
        $self->{thresholds}->{$metric}->{critical});
  } else {
    return ($self->{thresholds}->{default}->{warning},
        $self->{thresholds}->{default}->{critical});
  }
}

sub check_thresholds {
  my $self = shift;
  my @params = @_;
  my $level = $ERRORS{OK};
  my $warningrange;
  my $criticalrange;
  my $value;
  if (scalar(@params) > 1) {
    my %params = @params;
    $value = $params{value};
    my $metric = $params{metric};
    if ($metric ne 'default') {
      $warningrange = exists $self->{thresholds}->{$metric}->{warning} ?
          $self->{thresholds}->{$metric}->{warning} :
          $self->{thresholds}->{default}->{warning};
      $criticalrange = exists $self->{thresholds}->{$metric}->{critical} ?
          $self->{thresholds}->{$metric}->{critical} :
          $self->{thresholds}->{default}->{critical};
    } else {
      $warningrange = (defined $params{warning}) ?
          $params{warning} : $self->{thresholds}->{default}->{warning};
      $criticalrange = (defined $params{critical}) ?
          $params{critical} : $self->{thresholds}->{default}->{critical};
    }
  } else {
    $value = $params[0];
    $warningrange = $self->{thresholds}->{default}->{warning};
    $criticalrange = $self->{thresholds}->{default}->{critical};
  }
  if (! defined $warningrange) {
    # there was no set_thresholds for defaults, no --warning, no --warningx
  } elsif ($warningrange =~ /^([-+]?[0-9]*\.?[0-9]+)$/) {
    # warning = 10, warn if > 10 or < 0
    $level = $ERRORS{WARNING}
        if ($value > $1 || $value < 0);
  } elsif ($warningrange =~ /^([-+]?[0-9]*\.?[0-9]+):$/) {
    # warning = 10:, warn if < 10
    $level = $ERRORS{WARNING}
        if ($value < $1);
  } elsif ($warningrange =~ /^~:([-+]?[0-9]*\.?[0-9]+)$/) {
    # warning = ~:10, warn if > 10
    $level = $ERRORS{WARNING}
        if ($value > $1);
  } elsif ($warningrange =~ /^([-+]?[0-9]*\.?[0-9]+):([-+]?[0-9]*\.?[0-9]+)$/) {
    # warning = 10:20, warn if < 10 or > 20
    $level = $ERRORS{WARNING}
        if ($value < $1 || $value > $2);
  } elsif ($warningrange =~ /^@([-+]?[0-9]*\.?[0-9]+):([-+]?[0-9]*\.?[0-9]+)$/) {
    # warning = @10:20, warn if >= 10 and <= 20
    $level = $ERRORS{WARNING}
        if ($value >= $1 && $value <= $2);
  }
  if (! defined $criticalrange) {
    # there was no set_thresholds for defaults, no --critical, no --criticalx
  } elsif ($criticalrange =~ /^([-+]?[0-9]*\.?[0-9]+)$/) {
    # critical = 10, crit if > 10 or < 0
    $level = $ERRORS{CRITICAL}
        if ($value > $1 || $value < 0);
  } elsif ($criticalrange =~ /^([-+]?[0-9]*\.?[0-9]+):$/) {
    # critical = 10:, crit if < 10
    $level = $ERRORS{CRITICAL}
        if ($value < $1);
  } elsif ($criticalrange =~ /^~:([-+]?[0-9]*\.?[0-9]+)$/) {
    # critical = ~:10, crit if > 10
    $level = $ERRORS{CRITICAL}
        if ($value > $1);
  } elsif ($criticalrange =~ /^([-+]?[0-9]*\.?[0-9]+):([-+]?[0-9]*\.?[0-9]+)$/) {
    # critical = 10:20, crit if < 10 or > 20
    $level = $ERRORS{CRITICAL}
        if ($value < $1 || $value > $2);
  } elsif ($criticalrange =~ /^@([-+]?[0-9]*\.?[0-9]+):([-+]?[0-9]*\.?[0-9]+)$/) {
    # critical = @10:20, crit if >= 10 and <= 20
    $level = $ERRORS{CRITICAL}
        if ($value >= $1 && $value <= $2);
  }
  return $level;
}


package Monitoring::GLPlugin::Commandline::Getopt;
use strict;
use File::Basename;
use Getopt::Long qw(:config no_ignore_case bundling);

# Standard defaults
my %DEFAULT = (
  timeout => 15,
  verbose => 0,
  license =>
"This monitoring plugin is free software, and comes with ABSOLUTELY NO WARRANTY.
It may be used, redistributed and/or modified under the terms of the GNU
General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).",
);
# Standard arguments
my @ARGS = ({
    spec => 'usage|?',
    help => "-?, --usage\n   Print usage information",
  }, {
    spec => 'help|h',
    help => "-h, --help\n   Print detailed help screen",
  }, {
    spec => 'version|V',
    help => "-V, --version\n   Print version information",
  }, {
    #spec => 'extra-opts:s@',
    #help => "--extra-opts=[<section>[@<config_file>]]\n   Section and/or config_file from which to load extra options (may repeat)",
  }, {
    spec => 'timeout|t=i',
    help => sprintf("-t, --timeout=INTEGER\n   Seconds before plugin times out (default: %s)", $DEFAULT{timeout}),
    default => $DEFAULT{timeout},
  }, {
    spec => 'verbose|v+',
    help => "-v, --verbose\n   Show details for command-line debugging (can repeat up to 3 times)",
    default => $DEFAULT{verbose},
  },
);
# Standard arguments we traditionally display last in the help output
my %DEFER_ARGS = map { $_ => 1 } qw(timeout verbose);

sub _init {
  my $self = shift;
  my %params = @_;
  # Check params
  my %attr = (
    usage => 1,
    version => 0,
    url => 0,
    plugin => { default => $Monitoring::GLPlugin::pluginname },
    blurb => 0,
    extra => 0,
    'extra-opts' => 0,
    license => { default => $DEFAULT{license} },
    timeout => { default => $DEFAULT{timeout} },
  );

  # Add attr to private _attr hash (except timeout)
  $self->{timeout} = delete $attr{timeout};
  $self->{_attr} = { %attr };
  foreach (keys %{$self->{_attr}}) {
    if (exists $params{$_}) {
      $self->{_attr}->{$_} = $params{$_};
    } else {
      $self->{_attr}->{$_} = $self->{_attr}->{$_}->{default}
          if ref ($self->{_attr}->{$_}) eq 'HASH' &&
              exists $self->{_attr}->{$_}->{default};
    }
  }
  # Chomp _attr values
  chomp foreach values %{$self->{_attr}};

  # Setup initial args list
  $self->{_args} = [ grep { exists $_->{spec} } @ARGS ];

  $self
}

sub new {
  my $class = shift;
  my $self = bless {}, $class;
  $self->_init(@_);
}

sub add_arg {
  my $self = shift;
  my %arg = @_;
  push (@{$self->{_args}}, \%arg);
}

sub mod_arg {
  my $self = shift;
  my $argname = shift;
  my %arg = @_;
  foreach my $old_arg (@{$self->{_args}}) {
    next unless $old_arg->{spec} =~ /(\w+).*/ && $argname eq $1;
    foreach my $key (keys %arg) {
      $old_arg->{$key} = $arg{$key};
    }
  }
}

sub getopts {
  my $self = shift;
  my %commandline = ();
  my @params = map { $_->{spec} } @{$self->{_args}};
  if (! GetOptions(\%commandline, @params)) {
    $self->print_help();
    exit 0;
  } else {
    no strict 'refs';
    no warnings 'redefine';
    do { $self->print_help(); exit 0; } if $commandline{help};
    do { $self->print_version(); exit 0 } if $commandline{version};
    do { $self->print_usage(); exit 3 } if $commandline{usage};
    foreach (map { $_->{spec} =~ /^([\w\-]+)/; $1; } @{$self->{_args}}) {
      my $field = $_;
      *{"$field"} = sub {
        return $self->{opts}->{$field};
      };
    }
    foreach (map { $_->{spec} =~ /^([\w\-]+)/; $1; }
        grep { exists $_->{required} && $_->{required} } @{$self->{_args}}) {
      do { $self->print_usage(); exit 0 } if ! exists $commandline{$_};
    }
    foreach (grep { exists $_->{default} } @{$self->{_args}}) {
      $_->{spec} =~ /^([\w\-]+)/;
      my $spec = $1;
      $self->{opts}->{$spec} = $_->{default};
    }
    foreach (keys %commandline) {
      $self->{opts}->{$_} = $commandline{$_};
    }
    foreach (grep { exists $_->{env} } @{$self->{_args}}) {
      $_->{spec} =~ /^([\w\-]+)/;
      my $spec = $1;
      if (exists $ENV{'NAGIOS__HOST'.$_->{env}}) {
        $self->{opts}->{$spec} = $ENV{'NAGIOS__HOST'.$_->{env}};
      }
      if (exists $ENV{'NAGIOS__SERVICE'.$_->{env}}) {
        $self->{opts}->{$spec} = $ENV{'NAGIOS__SERVICE'.$_->{env}};
      }
    }
    foreach (grep { exists $_->{aliasfor} } @{$self->{_args}}) {
      my $field = $_->{aliasfor};
      $_->{spec} =~ /^([\w\-]+)/;
      my $aliasfield = $1;
      next if $self->{opts}->{$field};
      *{"$field"} = sub {
        return $self->{opts}->{$aliasfield};
      };
    }
  }
}

sub create_opt {
  my $self = shift;
  my $key = shift;
  no strict 'refs';
  *{"$key"} = sub {
      return $self->{opts}->{$key};
  };
}

sub override_opt {
  my $self = shift;
  my $key = shift;
  my $value = shift;
  $self->{opts}->{$key} = $value;
}

sub get {
  my $self = shift;
  my $opt = shift;
  return $self->{opts}->{$opt};
}

sub print_help {
  my $self = shift;
  $self->print_version();
  printf "\n%s\n", $self->{_attr}->{license};
  printf "\n%s\n\n", $self->{_attr}->{blurb};
  $self->print_usage();
  foreach (grep {
      ! (exists $_->{hidden} && $_->{hidden}) 
  } @{$self->{_args}}) {
    printf " %s\n", $_->{help};
  }
  exit 0;
}

sub print_usage {
  my $self = shift;
  printf $self->{_attr}->{usage}, $self->{_attr}->{plugin};
  print "\n";
}

sub print_version {
  my $self = shift;
  printf "%s %s", $self->{_attr}->{plugin}, $self->{_attr}->{version};
  printf " [%s]", $self->{_attr}->{url} if $self->{_attr}->{url};
  print "\n";
}

sub print_license {
  my $self = shift;
  printf "%s\n", $self->{_attr}->{license};
  print "\n";
}


package Monitoring::GLPlugin::Item;
our @ISA = qw(Monitoring::GLPlugin);

use strict;

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {
    blacklisted => 0,
    info => undef,
    extendedinfo => undef,
  };
  bless $self, $class;
  $self->init(%params);
  return $self;
}

sub check {
  my $self = shift;
  my $lists = shift;
  my @lists = $lists ? @{$lists} : grep { ref($self->{$_}) eq "ARRAY" } keys %{$self};
  foreach my $list (@lists) {
    $self->add_info('checking '.$list);
    foreach my $element (@{$self->{$list}}) {
      $element->blacklist() if $self->is_blacklisted();
      $element->check();
    }
  }
}


package Monitoring::GLPlugin::TableItem;
our @ISA = qw(Monitoring::GLPlugin::Item);

use strict;

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {};
  bless $self, $class;
  foreach (keys %params) {
    $self->{$_} = $params{$_};
  }
  if ($self->can("finish")) {
    $self->finish(%params);
  }
  return $self;
}

sub check {
  my $self = shift;
  # some tableitems are not checkable, they are only used to enhance other
  # items (e.g. sensorthresholds enhance sensors)
  # normal tableitems should have their own check-method
}


package Monitoring::GLPlugin::SNMP;
our @ISA = qw(Monitoring::GLPlugin);

use strict;
use File::Basename;
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use AutoLoader;
our $AUTOLOAD;

use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

{
  our $mode = undef;
  our $plugin = undef;
  our $blacklist = undef;
  our $session = undef;
  our $rawdata = {};
  our $tablecache = {};
  our $info = [];
  our $extendedinfo = [];
  our $summary = [];
  our $oidtrace = [];
  our $uptime = 0;
}

sub v2tov3 {
  my $self = shift;
  if ($self->opts->community && $self->opts->community =~ /^snmpv3(.)(.+)/) {
    my $separator = $1;
    my ($authprotocol, $authpassword, $privprotocol, $privpassword,
        $username, $contextengineid, $contextname) = split(/$separator/, $2);
    $self->override_opt('authprotocol', $authprotocol) 
        if defined($authprotocol) && $authprotocol;
    $self->override_opt('authpassword', $authpassword) 
        if defined($authpassword) && $authpassword;
    $self->override_opt('privprotocol', $privprotocol) 
        if defined($privprotocol) && $privprotocol;
    $self->override_opt('privpassword', $privpassword) 
        if defined($privpassword) && $privpassword;
    $self->override_opt('username', $username) 
        if defined($username) && $username;
    $self->override_opt('contextengineid', $contextengineid) 
        if defined($contextengineid) && $contextengineid;
    $self->override_opt('contextname', $contextname) 
        if defined($contextname) && $contextname;
    $self->override_opt('protocol', '3') ;
  }
  if (($self->opts->authpassword || $self->opts->authprotocol ||
      $self->opts->privpassword || $self->opts->privprotocol) && 
      ! $self->opts->protocol eq '3') {
    $self->override_opt('protocol', '3') ;
  }
}

sub add_snmp_args {
  my $self = shift;
  $self->add_arg(
      spec => 'hostname|H=s',
      help => '--hostname
   Hostname or IP-address of the switch or router',
      required => 0,
      env => 'HOSTNAME',
  );
  $self->add_arg(
      spec => 'port=i',
      help => '--port
   The SNMP port to use (default: 161)',
      required => 0,
      default => 161,
  );
  $self->add_arg(
      spec => 'domain=s',
      help => '--domain
   The transport domain to use (default: udp/ipv4, other possible values: udp6, udp/ipv6, tcp, tcp4, tcp/ipv4, tcp6, tcp/ipv6)',
      required => 0,
      default => 'udp',
  );
  $self->add_arg(
      spec => 'protocol|P=s',
      help => '--protocol
   The SNMP protocol to use (default: 2c, other possibilities: 1,3)',
      required => 0,
      default => '2c',
  );
  $self->add_arg(
      spec => 'community|C=s',
      help => '--community
   SNMP community of the server (SNMP v1/2 only)',
      required => 0,
      default => 'public',
  );
  $self->add_arg(
      spec => 'username:s',
      help => '--username
   The securityName for the USM security model (SNMPv3 only)',
      required => 0,
  );
  $self->add_arg(
      spec => 'authpassword:s',
      help => '--authpassword
   The authentication password for SNMPv3',
      required => 0,
  );
  $self->add_arg(
      spec => 'authprotocol:s',
      help => '--authprotocol
   The authentication protocol for SNMPv3 (md5|sha)',
      required => 0,
  );
  $self->add_arg(
      spec => 'privpassword:s',
      help => '--privpassword
   The password for authPriv security level',
      required => 0,
  );
  $self->add_arg(
      spec => 'privprotocol=s',
      help => '--privprotocol
   The private protocol for SNMPv3 (des|aes|aes128|3des|3desde)',
      required => 0,
  );
  $self->add_arg(
      spec => 'contextengineid=s',
      help => '--contextengineid
   The context engine id for SNMPv3 (10 to 64 hex characters)',
      required => 0,
  );
  $self->add_arg(
      spec => 'contextname=s',
      help => '--contextname
   The context name for SNMPv3 (empty represents the "default" context)',
      required => 0,
  );
  $self->add_arg(
      spec => 'community2=s',
      help => '--community2
   SNMP community which can be used to switch the context during runtime',
      required => 0,
  );
  $self->add_arg(
      spec => 'snmpwalk=s',
      help => '--snmpwalk
   A file with the output of a snmpwalk (used for simulation)
   Use it instead of --hostname',
      required => 0,
      env => 'SNMPWALK',
  );
  $self->add_arg(
      spec => 'oids=s',
      help => '--oids
   A list of oids which are downloaded and written to a cache file.
   Use it together with --mode oidcache',
      required => 0,
  );
  $self->add_arg(
      spec => 'offline:i',
      help => '--offline
   The maximum number of seconds since the last update of cache file before
   it is considered too old',
      required => 0,
      env => 'OFFLINE',
  );
}

sub validate_args {
  my $self = shift;
  $self->SUPER::validate_args();
  if ($self->opts->mode eq 'walk') {
    if ($self->opts->snmpwalk && $self->opts->hostname) {
      if ($self->check_messages == CRITICAL) {
        # gemecker vom super-validierer, der sicherstellt, dass die datei
        # snmpwalk existiert. in diesem fall wird sie aber erst neu angelegt,
        # also schnauze.
        my ($code, $message) = $self->check_messages;
        if ($message eq sprintf("file %s not found", $self->opts->snmpwalk)) {
          $self->clear_critical;
        }
      }
      # snmp agent wird abgefragt, die ergebnisse landen in einem file
      # opts->snmpwalk ist der filename. da sich die ganzen get_snmp_table/object-aufrufe
      # an das walkfile statt an den agenten halten wuerden, muss opts->snmpwalk geloescht
      # werden. stattdessen wird opts->snmpdump als traeger des dateinamens mitgegeben.
      # nur sinnvoll mit mode=walk
      $self->create_opt('snmpdump');
      $self->override_opt('snmpdump', $self->opts->snmpwalk);
      $self->override_opt('snmpwalk', undef);
    } elsif (! $self->opts->snmpwalk && $self->opts->hostname && $self->opts->mode eq 'walk') {   
      # snmp agent wird abgefragt, die ergebnisse landen in einem file, dessen name
      # nicht vorgegeben ist
      $self->create_opt('snmpdump');
    }
  } else {    
    if ($self->opts->snmpwalk && ! $self->opts->hostname) {
      # normaler aufruf, mode != walk, oid-quelle ist eine datei
      $self->override_opt('hostname', 'snmpwalk.file'.md5_hex($self->opts->snmpwalk))
    } elsif ($self->opts->snmpwalk && $self->opts->hostname) {
      # snmpwalk hat vorrang
      $self->override_opt('hostname', undef);
    }
  }
}

sub init {
  my $self = shift;
  if ($self->mode =~ /device::walk/) {
    my @trees = ();
    my $name = $Monitoring::GLPlugin::pluginname;
    $name =~ s/.*\///g;
    $name = sprintf "/tmp/snmpwalk_%s_%s", $name, $self->opts->hostname;
    if ($self->opts->oids) {
      # create pid filename
      # already running?;x
      @trees = split(",", $self->opts->oids);

    } elsif ($self->can("trees")) {
      @trees = $self->trees;
      push(@trees, "1.3.6.1.2.1.1");
    } else {
      @trees = ("1.3.6.1.2.1", "1.3.6.1.4.1");
    }
    if ($self->opts->snmpdump) {
      $name = $self->opts->snmpdump;
    }
    $self->opts->override_opt("protocol", $1) if $self->opts->protocol =~ /^v(.*)/;
    if (defined $self->opts->offline) {
      $self->{pidfile} = $name.".pid";
      if (! $self->check_pidfile()) {
        $self->debug("Exiting because another walk is already running");
        printf STDERR "Exiting because another walk is already running\n";
        exit 3;
      }
      $self->write_pidfile();
      my $timedout = 0;
      my $snmpwalkpid = 0;
      $SIG{'ALRM'} = sub {
        $timedout = 1;
        printf "UNKNOWN - %s timed out after %d seconds\n",
            $Monitoring::GLPlugin::plugin->{name}, $self->opts->timeout;
        kill 9, $snmpwalkpid;
      };
      alarm($self->opts->timeout);
      unlink $name.".partial";
      while (! $timedout && @trees) {
        my $tree = shift @trees;
        $SIG{CHLD} = 'IGNORE';
        my $cmd = sprintf "snmpwalk -ObentU -v%s -c %s %s %s >> %s", 
            $self->opts->protocol,
            $self->opts->community,
            $self->opts->hostname,
            $tree, $name.".partial";
        $self->debug($cmd);
        $snmpwalkpid = fork;
        if (not $snmpwalkpid) {
          exec($cmd);
        } else {
          wait();
        }
      }
      rename $name.".partial", $name if ! $timedout;
      -f $self->{pidfile} && unlink $self->{pidfile};
      if ($timedout) {
        printf "CRITICAL - timeout. There are still %d snmpwalks left\n", scalar(@trees);
        exit 3;
      } else {
        printf "OK - all requested oids are in %s\n", $name;
      }
    } else {
      printf "rm -f %s\n", $name;
      foreach (@trees) {
        printf "snmpwalk -ObentU -v%s -c %s %s %s >> %s\n", 
            $self->opts->protocol,
            $self->opts->community,
            $self->opts->hostname,
            $_, $name;
      }
    }
    exit 0;
  } elsif ($self->mode =~ /device::uptime/) {
    $self->add_info(sprintf 'device is up since %s',
        $self->human_timeticks($self->{uptime}));
    $self->set_thresholds(warning => '15:', critical => '5:');
    $self->add_message($self->check_thresholds($self->{uptime} / 60));
    $self->add_perfdata(
        label => 'uptime',
        value => $self->{uptime} / 60,
        places => 0,
    );
    my ($code, $message) = $self->check_messages(join => ', ', join_all => ', ');
    $Monitoring::GLPlugin::plugin->nagios_exit($code, $message);
  } elsif ($self->mode =~ /device::supportedmibs/) {
    our $mibdepot = [];
    my $unknowns = {};
    my @outputlist = ();
    %{$unknowns} = %{$self->rawdata};
    if ($self->opts->name && -f $self->opts->name) {
      eval { require $self->opts->name };
      $self->add_critical($@) if $@;
    } elsif ($self->opts->name && ! -f $self->opts->name) {
      $self->add_unknown("where is --name mibdepotfile?");
    }
    push(@{$mibdepot}, ['1.3.6.1.2.1.60', 'ietf', 'v2', 'ACCOUNTING-CONTROL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.238', 'ietf', 'v2', 'ADSL2-LINE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.238.2', 'ietf', 'v2', 'ADSL2-LINE-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.94.3', 'ietf', 'v2', 'ADSL-LINE-EXT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.94', 'ietf', 'v2', 'ADSL-LINE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.94.2', 'ietf', 'v2', 'ADSL-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.74', 'ietf', 'v2', 'AGENTX-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.123', 'ietf', 'v2', 'AGGREGATE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.118', 'ietf', 'v2', 'ALARM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.23', 'ietf', 'v2', 'APM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.3', 'ietf', 'v2', 'APPC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.13.1', 'ietf', 'v1', 'APPLETALK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.27', 'ietf', 'v2', 'APPLICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.62', 'ietf', 'v2', 'APPLICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.5', 'ietf', 'v2', 'APPN-DLUR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.4', 'ietf', 'v2', 'APPN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.4', 'ietf', 'v2', 'APPN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.4.0', 'ietf', 'v2', 'APPN-TRAP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.49', 'ietf', 'v2', 'APS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.117', 'ietf', 'v2', 'ARC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.37.1.14', 'ietf', 'v2', 'ATM2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.59', 'ietf', 'v2', 'ATM-ACCOUNTING-INFORMATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.37', 'ietf', 'v2', 'ATM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.37', 'ietf', 'v2', 'ATM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.37.3', 'ietf', 'v2', 'ATM-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.15', 'ietf', 'v2', 'BGP4-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.15', 'ietf', 'v2', 'BGP4-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.122', 'ietf', 'v2', 'BLDG-HVAC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17.1', 'ietf', 'v1', 'BRIDGE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17', 'ietf', 'v2', 'BRIDGE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.19', 'ietf', 'v2', 'CHARACTER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.94', 'ietf', 'v2', 'CIRCUIT-IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.1.1', 'ietf', 'v1', 'CLNS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.1.1', 'ietf', 'v1', 'CLNS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.132', 'ietf', 'v2', 'COFFEE-POT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.89', 'ietf', 'v2', 'COPS-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.18.1', 'ietf', 'v1', 'DECNET-PHIV-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.21', 'ietf', 'v2', 'DIAL-CONTROL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.108', 'ietf', 'v2', 'DIFFSERV-CONFIG-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.97', 'ietf', 'v2', 'DIFFSERV-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.66', 'ietf', 'v2', 'DIRECTORY-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.88', 'ietf', 'v2', 'DISMAN-EVENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.90', 'ietf', 'v2', 'DISMAN-EXPRESSION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.82', 'ietf', 'v2', 'DISMAN-NSLOOKUP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.82', 'ietf', 'v2', 'DISMAN-NSLOOKUP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.80', 'ietf', 'v2', 'DISMAN-PING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.80', 'ietf', 'v2', 'DISMAN-PING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.63', 'ietf', 'v2', 'DISMAN-SCHEDULE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.63', 'ietf', 'v2', 'DISMAN-SCHEDULE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.64', 'ietf', 'v2', 'DISMAN-SCRIPT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.64', 'ietf', 'v2', 'DISMAN-SCRIPT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.81', 'ietf', 'v2', 'DISMAN-TRACEROUTE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.81', 'ietf', 'v2', 'DISMAN-TRACEROUTE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.46', 'ietf', 'v2', 'DLSW-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.32.2', 'ietf', 'v2', 'DNS-RESOLVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.32.1', 'ietf', 'v2', 'DNS-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.127.5', 'ietf', 'v2', 'DOCS-BPI-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.69', 'ietf', 'v2', 'DOCS-CABLE-DEVICE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.69', 'ietf', 'v2', 'DOCS-CABLE-DEVICE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.126', 'ietf', 'v2', 'DOCS-IETF-BPI2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.132', 'ietf', 'v2', 'DOCS-IETF-CABLE-DEVICE-NOTIFICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.127', 'ietf', 'v2', 'DOCS-IETF-QOS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.125', 'ietf', 'v2', 'DOCS-IETF-SUBMGT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.127', 'ietf', 'v2', 'DOCS-IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.127', 'ietf', 'v2', 'DOCS-IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.45', 'ietf', 'v2', 'DOT12-IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.53', 'ietf', 'v2', 'DOT12-RPTR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.155', 'ietf', 'v2', 'DOT3-EPON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.158', 'ietf', 'v2', 'DOT3-OAM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.2.2.1.1', 'ietf', 'v1', 'DPI20-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.82', 'ietf', 'v2', 'DS0BUNDLE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.81', 'ietf', 'v2', 'DS0-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.18', 'ietf', 'v2', 'DS1-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.18', 'ietf', 'v2', 'DS1-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.18', 'ietf', 'v2', 'DS1-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.30', 'ietf', 'v2', 'DS3-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.30', 'ietf', 'v2', 'DS3-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.29', 'ietf', 'v2', 'DSA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.26', 'ietf', 'v2', 'DSMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.7', 'ietf', 'v2', 'EBN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.167', 'ietf', 'v2', 'EFM-CU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.47', 'ietf', 'v2', 'ENTITY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.47', 'ietf', 'v2', 'ENTITY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.47', 'ietf', 'v2', 'ENTITY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.99', 'ietf', 'v2', 'ENTITY-SENSOR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.131', 'ietf', 'v2', 'ENTITY-STATE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.130', 'ietf', 'v2', 'ENTITY-STATE-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.70', 'ietf', 'v2', 'ETHER-CHIPSET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.7', 'ietf', 'v1', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.7', 'ietf', 'v1', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.35', 'ietf', 'v2', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.35', 'ietf', 'v2', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.35', 'ietf', 'v2', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.35', 'ietf', 'v2', 'EtherLike-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.224', 'ietf', 'v2', 'FCIP-MGMT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.56', 'ietf', 'v2', 'FC-MGMT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.15.73.1', 'ietf', 'v1', 'FDDI-SMT73-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.75', 'ietf', 'v2', 'FIBRE-CHANNEL-FE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.111', 'ietf', 'v2', 'Finisher-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.40', 'ietf', 'v2', 'FLOW-METER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.40', 'ietf', 'v2', 'FLOW-METER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.32', 'ietf', 'v2', 'FRAME-RELAY-DTE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.86', 'ietf', 'v2', 'FR-ATM-PVC-SERVICE-IWF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.47', 'ietf', 'v2', 'FR-MFR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.44', 'ietf', 'v2', 'FRNETSERV-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.44', 'ietf', 'v2', 'FRNETSERV-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.44', 'ietf', 'v2', 'FRNETSERV-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.95', 'ietf', 'v2', 'FRSLD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.16', 'ietf', 'v2', 'GMPLS-LABEL-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.15', 'ietf', 'v2', 'GMPLS-LSR-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.12', 'ietf', 'v2', 'GMPLS-TC-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.13', 'ietf', 'v2', 'GMPLS-TE-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.98', 'ietf', 'v2', 'GSMP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.29', 'ietf', 'v2', 'HC-ALARM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.107', 'ietf', 'v2', 'HC-PerfHist-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.20.5', 'ietf', 'v2', 'HC-RMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.25.1', 'ietf', 'v1', 'HOST-RESOURCES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.25.7.1', 'ietf', 'v2', 'HOST-RESOURCES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.6.1.5', 'ietf', 'v2', 'HPR-IP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.6', 'ietf', 'v2', 'HPR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.106', 'ietf', 'v2', 'IANA-CHARSET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.110', 'ietf', 'v2', 'IANA-FINISHER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.152', 'ietf', 'v2', 'IANA-GMPLS-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.30', 'ietf', 'v2', 'IANAifType-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.128', 'ietf', 'v2', 'IANA-IPPM-METRICS-REGISTRY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.119', 'ietf', 'v2', 'IANA-ITU-ALARM-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.154', 'ietf', 'v2', 'IANA-MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.109', 'ietf', 'v2', 'IANA-PRINTER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.2.6.2.13.1.1', 'ietf', 'v1', 'IBM-6611-APPN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.166', 'ietf', 'v2', 'IF-CAP-STACK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.230', 'ietf', 'v2', 'IFCP-MGMT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.77', 'ietf', 'v2', 'IF-INVERTED-STACK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.31', 'ietf', 'v2', 'IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.31', 'ietf', 'v2', 'IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.31', 'ietf', 'v2', 'IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.85', 'ietf', 'v2', 'IGMP-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.76', 'ietf', 'v2', 'INET-ADDRESS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.76', 'ietf', 'v2', 'INET-ADDRESS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.76', 'ietf', 'v2', 'INET-ADDRESS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.52.5', 'ietf', 'v2', 'INTEGRATED-SERVICES-GUARANTEED-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.52', 'ietf', 'v2', 'INTEGRATED-SERVICES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.27', 'ietf', 'v2', 'INTERFACETOPN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.17', 'ietf', 'v2', 'IPATM-IPMC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.57', 'ietf', 'v2', 'IPATM-IPMC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.4.24', 'ietf', 'v2', 'IP-FORWARD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.4.24', 'ietf', 'v2', 'IP-FORWARD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.168', 'ietf', 'v2', 'IPMCAST-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.48', 'ietf', 'v2', 'IP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.48', 'ietf', 'v2', 'IP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.83', 'ietf', 'v2', 'IPMROUTE-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.46', 'ietf', 'v2', 'IPOA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.141', 'ietf', 'v2', 'IPS-AUTH-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.153', 'ietf', 'v2', 'IPSEC-SPD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.103', 'ietf', 'v2', 'IPV6-FLOW-LABEL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.56', 'ietf', 'v2', 'IPV6-ICMP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.55', 'ietf', 'v2', 'IPV6-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.91', 'ietf', 'v2', 'IPV6-MLD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.86', 'ietf', 'v2', 'IPV6-TCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.87', 'ietf', 'v2', 'IPV6-UDP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.142', 'ietf', 'v2', 'ISCSI-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.20', 'ietf', 'v2', 'ISDN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.138', 'ietf', 'v2', 'ISIS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.163', 'ietf', 'v2', 'ISNS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.121', 'ietf', 'v2', 'ITU-ALARM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.120', 'ietf', 'v2', 'ITU-ALARM-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.2699.1.1', 'ietf', 'v2', 'Job-Monitoring-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.95', 'ietf', 'v2', 'L2TP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.165', 'ietf', 'v2', 'LANGTAG-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.227', 'ietf', 'v2', 'LMP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.227', 'ietf', 'v2', 'LMP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.101', 'ietf', 'v2', 'MALLOC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.26.1', 'ietf', 'v1', 'MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.26.6', 'ietf', 'v2', 'MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.26.6', 'ietf', 'v2', 'MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.26.6', 'ietf', 'v2', 'MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.26.6', 'ietf', 'v2', 'MAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.171', 'ietf', 'v2', 'MIDCOM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.38.1', 'ietf', 'v1', 'MIOX25-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.44', 'ietf', 'v2', 'MIP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.133', 'ietf', 'v2', 'MOBILEIPV6-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.38', 'ietf', 'v2', 'Modem-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.8', 'ietf', 'v2', 'MPLS-FTN-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.11', 'ietf', 'v2', 'MPLS-L3VPN-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.9', 'ietf', 'v2', 'MPLS-LC-ATM-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.10', 'ietf', 'v2', 'MPLS-LC-FR-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.5', 'ietf', 'v2', 'MPLS-LDP-ATM-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.6', 'ietf', 'v2', 'MPLS-LDP-FRAME-RELAY-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.7', 'ietf', 'v2', 'MPLS-LDP-GENERIC-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.9.10.65', 'ietf', 'v2', 'MPLS-LDP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.4', 'ietf', 'v2', 'MPLS-LDP-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.2', 'ietf', 'v2', 'MPLS-LSR-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.1', 'ietf', 'v2', 'MPLS-TC-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.166.3', 'ietf', 'v2', 'MPLS-TE-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.92', 'ietf', 'v2', 'MSDP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.28', 'ietf', 'v2', 'MTA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.28', 'ietf', 'v2', 'MTA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.28', 'ietf', 'v2', 'MTA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.123', 'ietf', 'v2', 'NAT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.27', 'ietf', 'v2', 'NETWORK-SERVICES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.27', 'ietf', 'v2', 'NETWORK-SERVICES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.71', 'ietf', 'v2', 'NHRP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.92', 'ietf', 'v2', 'NOTIFICATION-LOG-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.133', 'ietf', 'v2', 'OPT-IF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.14', 'ietf', 'v2', 'OSPF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.14', 'ietf', 'v2', 'OSPF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.14.16', 'ietf', 'v2', 'OSPF-TRAP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.14.16', 'ietf', 'v2', 'OSPF-TRAP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.34', 'ietf', 'v2', 'PARALLEL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17.6', 'ietf', 'v2', 'P-BRIDGE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.58', 'ietf', 'v2', 'PerfHist-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.58', 'ietf', 'v2', 'PerfHist-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.172', 'ietf', 'v2', 'PIM-BSR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.61', 'ietf', 'v2', 'PIM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.157', 'ietf', 'v2', 'PIM-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.93', 'ietf', 'v2', 'PINT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.140', 'ietf', 'v2', 'PKTC-IETF-MTA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.169', 'ietf', 'v2', 'PKTC-IETF-SIG-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.124', 'ietf', 'v2', 'POLICY-BASED-MANAGEMENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.105', 'ietf', 'v2', 'POWER-ETHERNET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.23.4', 'ietf', 'v1', 'PPP-BRIDGE-NCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.23.3', 'ietf', 'v1', 'PPP-IP-NCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.23.1.1', 'ietf', 'v1', 'PPP-LCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.23.2', 'ietf', 'v1', 'PPP-SEC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.43', 'ietf', 'v2', 'Printer-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.43', 'ietf', 'v2', 'Printer-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.79', 'ietf', 'v2', 'PTOPO-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17.7', 'ietf', 'v2', 'Q-BRIDGE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.2.2', 'ietf', 'v2', 'RADIUS-ACC-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.2.2', 'ietf', 'v2', 'RADIUS-ACC-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.2.1', 'ietf', 'v2', 'RADIUS-ACC-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.2.1', 'ietf', 'v2', 'RADIUS-ACC-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.1.2', 'ietf', 'v2', 'RADIUS-AUTH-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.1.2', 'ietf', 'v2', 'RADIUS-AUTH-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.1.1', 'ietf', 'v2', 'RADIUS-AUTH-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.67.1.1', 'ietf', 'v2', 'RADIUS-AUTH-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.145', 'ietf', 'v2', 'RADIUS-DYNAUTH-CLIENT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.146', 'ietf', 'v2', 'RADIUS-DYNAUTH-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.31', 'ietf', 'v2', 'RAQMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.32', 'ietf', 'v2', 'RAQMON-RDS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.39', 'ietf', 'v2', 'RDBMS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.1', 'ietf', 'v1', 'RFC1066-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.1', 'ietf', 'v1', 'RFC1156-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.1', 'ietf', 'v1', 'RFC1158-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.1', 'ietf', 'v1', 'RFC1213-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.12', 'ietf', 'v1', 'RFC1229-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.7', 'ietf', 'v1', 'RFC1230-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.9', 'ietf', 'v1', 'RFC1231-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.2', 'ietf', 'v1', 'RFC1232-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.15', 'ietf', 'v1', 'RFC1233-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.13.1', 'ietf', 'v1', 'RFC1243-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.13.1', 'ietf', 'v1', 'RFC1248-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.13.1', 'ietf', 'v1', 'RFC1252-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.14.1', 'ietf', 'v1', 'RFC1253-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.15', 'ietf', 'v1', 'RFC1269-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.1', 'ietf', 'v1', 'RFC1271-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.7', 'ietf', 'v1', 'RFC1284-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.15.1', 'ietf', 'v1', 'RFC1285-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17.1', 'ietf', 'v1', 'RFC1286-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.18.1', 'ietf', 'v1', 'RFC1289-phivMIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.31', 'ietf', 'v1', 'RFC1304-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.32', 'ietf', 'v1', 'RFC1315-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.19', 'ietf', 'v1', 'RFC1316-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.33', 'ietf', 'v1', 'RFC1317-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.34', 'ietf', 'v1', 'RFC1318-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.20.2', 'ietf', 'v1', 'RFC1353-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.4.24', 'ietf', 'v1', 'RFC1354-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.16', 'ietf', 'v1', 'RFC1381-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.5', 'ietf', 'v1', 'RFC1382-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.23.1', 'ietf', 'v1', 'RFC1389-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.7', 'ietf', 'v1', 'RFC1398-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.18', 'ietf', 'v1', 'RFC1406-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.30', 'ietf', 'v1', 'RFC1407-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.24.1', 'ietf', 'v1', 'RFC1414-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.23', 'ietf', 'v2', 'RIPv2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16', 'ietf', 'v2', 'RMON2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16', 'ietf', 'v2', 'RMON2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.1', 'ietf', 'v1', 'RMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.20.8', 'ietf', 'v2', 'RMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.112', 'ietf', 'v2', 'ROHC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.114', 'ietf', 'v2', 'ROHC-RTP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.113', 'ietf', 'v2', 'ROHC-UNCOMPRESSED-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.33', 'ietf', 'v2', 'RS-232-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.134', 'ietf', 'v2', 'RSTP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.51', 'ietf', 'v2', 'RSVP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.87', 'ietf', 'v2', 'RTP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.139', 'ietf', 'v2', 'SCSI-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.104', 'ietf', 'v2', 'SCTP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.4300.1', 'ietf', 'v2', 'SFLOW-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.149', 'ietf', 'v2', 'SIP-COMMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.36', 'ietf', 'v2', 'SIP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.151', 'ietf', 'v2', 'SIP-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.148', 'ietf', 'v2', 'SIP-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.150', 'ietf', 'v2', 'SIP-UA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.88', 'ietf', 'v2', 'SLAPM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.22', 'ietf', 'v2', 'SMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.4.4', 'ietf', 'v1', 'SMUX-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34', 'ietf', 'v2', 'SNA-NAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34', 'ietf', 'v2', 'SNA-NAU-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.41', 'ietf', 'v2', 'SNA-SDLC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.18', 'ietf', 'v2', 'SNMP-COMMUNITY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.18', 'ietf', 'v2', 'SNMP-COMMUNITY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.10', 'ietf', 'v2', 'SNMP-FRAMEWORK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.10', 'ietf', 'v2', 'SNMP-FRAMEWORK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.10', 'ietf', 'v2', 'SNMP-FRAMEWORK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.21', 'ietf', 'v2', 'SNMP-IEEE802-TM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.11', 'ietf', 'v2', 'SNMP-MPD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.11', 'ietf', 'v2', 'SNMP-MPD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.11', 'ietf', 'v2', 'SNMP-MPD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.13', 'ietf', 'v2', 'SNMP-NOTIFICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.13', 'ietf', 'v2', 'SNMP-NOTIFICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.13', 'ietf', 'v2', 'SNMP-NOTIFICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.14', 'ietf', 'v2', 'SNMP-PROXY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.14', 'ietf', 'v2', 'SNMP-PROXY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.14', 'ietf', 'v2', 'SNMP-PROXY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.22.1.1', 'ietf', 'v1', 'SNMP-REPEATER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.22.1.1', 'ietf', 'v1', 'SNMP-REPEATER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.22.5', 'ietf', 'v2', 'SNMP-REPEATER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.12', 'ietf', 'v2', 'SNMP-TARGET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.12', 'ietf', 'v2', 'SNMP-TARGET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.12', 'ietf', 'v2', 'SNMP-TARGET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.15', 'ietf', 'v2', 'SNMP-USER-BASED-SM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.15', 'ietf', 'v2', 'SNMP-USER-BASED-SM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.15', 'ietf', 'v2', 'SNMP-USER-BASED-SM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.20', 'ietf', 'v2', 'SNMP-USM-AES-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.101', 'ietf', 'v2', 'SNMP-USM-DH-OBJECTS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.2', 'ietf', 'v2', 'SNMPv2-M2M-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.1', 'ietf', 'v2', 'SNMPv2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.1', 'ietf', 'v2', 'SNMPv2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.1', 'ietf', 'v2', 'SNMPv2-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.3', 'ietf', 'v2', 'SNMPv2-PARTY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.6', 'ietf', 'v2', 'SNMPv2-USEC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.16', 'ietf', 'v2', 'SNMP-VIEW-BASED-ACM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.16', 'ietf', 'v2', 'SNMP-VIEW-BASED-ACM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.6.3.16', 'ietf', 'v2', 'SNMP-VIEW-BASED-ACM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.39', 'ietf', 'v2', 'SONET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.39', 'ietf', 'v2', 'SONET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.39', 'ietf', 'v2', 'SONET-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.17.3', 'ietf', 'v1', 'SOURCE-ROUTING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.28', 'ietf', 'v2', 'SSPM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.54', 'ietf', 'v2', 'SYSAPPL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.137', 'ietf', 'v2', 'T11-FC-FABRIC-ADDR-MGR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.162', 'ietf', 'v2', 'T11-FC-FABRIC-CONFIG-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.159', 'ietf', 'v2', 'T11-FC-FABRIC-LOCK-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.143', 'ietf', 'v2', 'T11-FC-FSPF-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.135', 'ietf', 'v2', 'T11-FC-NAME-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.144', 'ietf', 'v2', 'T11-FC-ROUTE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.161', 'ietf', 'v2', 'T11-FC-RSCN-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.176', 'ietf', 'v2', 'T11-FC-SP-AUTHENTICATION-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.178', 'ietf', 'v2', 'T11-FC-SP-POLICY-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.179', 'ietf', 'v2', 'T11-FC-SP-SA-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.175', 'ietf', 'v2', 'T11-FC-SP-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.177', 'ietf', 'v2', 'T11-FC-SP-ZONING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.147', 'ietf', 'v2', 'T11-FC-VIRTUAL-FABRIC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.160', 'ietf', 'v2', 'T11-FC-ZONE-SERVER-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.136', 'ietf', 'v2', 'T11-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.156', 'ietf', 'v2', 'TCP-ESTATS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.4.1.23.2.29.1', 'ietf', 'v1', 'TCPIPX-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.49', 'ietf', 'v2', 'TCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.49', 'ietf', 'v2', 'TCP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.200', 'ietf', 'v2', 'TE-LINK-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.122', 'ietf', 'v2', 'TE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.3.124', 'ietf', 'v2', 'TIME-AGGREGATE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.8', 'ietf', 'v2', 'TN3270E-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.34.9', 'ietf', 'v2', 'TN3270E-RT-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.9', 'ietf', 'v2', 'TOKENRING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.9', 'ietf', 'v2', 'TOKENRING-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.1', 'ietf', 'v1', 'TOKEN-RING-RMON-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.42', 'ietf', 'v2', 'TOKENRING-STATION-SR-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.16.30', 'ietf', 'v2', 'TPM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.100', 'ietf', 'v2', 'TRANSPORT-ADDRESS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.116', 'ietf', 'v2', 'TRIP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.115', 'ietf', 'v2', 'TRIP-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.131', 'ietf', 'v2', 'TUNNEL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.131', 'ietf', 'v2', 'TUNNEL-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.170', 'ietf', 'v2', 'UDPLITE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.50', 'ietf', 'v2', 'UDP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.50', 'ietf', 'v2', 'UDP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.33', 'ietf', 'v2', 'UPS-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.164', 'ietf', 'v2', 'URI-TC-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.229', 'ietf', 'v2', 'VDSL-LINE-EXT-MCM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.228', 'ietf', 'v2', 'VDSL-LINE-EXT-SCM-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.10.97', 'ietf', 'v2', 'VDSL-LINE-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.129', 'ietf', 'v2', 'VPN-TC-STD-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.68', 'ietf', 'v2', 'VRRP-MIB']);
    push(@{$mibdepot}, ['1.3.6.1.2.1.65', 'ietf', 'v2', 'WWW-MIB']);
    my $oids = $self->get_entries_by_walk(-varbindlist => [
        '1.3.6.1.2.1', '1.3.6.1.4.1',
    ]);
    foreach my $mibinfo (@{$mibdepot}) {
      next if $self->opts->protocol eq "1" && $mibinfo->[2] ne "v1";
      next if $self->opts->protocol ne "1" && $mibinfo->[2] eq "v1";
      $Monitoring::GLPlugin::SNMP::mib_ids->{$mibinfo->[3]} = $mibinfo->[0];
    }
    $Monitoring::GLPlugin::SNMP::mib_ids->{'SNMP-MIB2'} = "1.3.6.1.2.1";
    foreach my $mib (keys %{$Monitoring::GLPlugin::SNMP::mib_ids}) {
      if ($self->implements_mib($mib)) {
        push(@outputlist, [$mib, $Monitoring::GLPlugin::SNMP::mib_ids->{$mib}]);
        $unknowns = {@{[map {
            $_, $self->rawdata->{$_}
        } grep {
            substr($_, 0, length($Monitoring::GLPlugin::SNMP::mib_ids->{$mib})) ne
                $Monitoring::GLPlugin::SNMP::mib_ids->{$mib} || (
            substr($_, 0, length($Monitoring::GLPlugin::SNMP::mib_ids->{$mib})) eq
                $Monitoring::GLPlugin::SNMP::mib_ids->{$mib} &&
            substr($_, length($Monitoring::GLPlugin::SNMP::mib_ids->{$mib}), 1) ne ".")
        } keys %{$unknowns}]}};
      }
    }
    my $toplevels = {};
    map {
        /^(1\.3\.6\.1\.(2|4)\.1\.\d+\.\d+)\./; $toplevels->{$1} = 1; 
    } keys %{$unknowns};
    foreach (sort {$a cmp $b} keys %{$toplevels}) {
      push(@outputlist, ["<unknown>", $_]);
    }
    foreach (sort {$a->[0] cmp $b->[0]} @outputlist) {
      printf "implements %s %s\n", $_->[0], $_->[1];
    }
    $self->add_ok("have fun");
    my ($code, $message) = $self->check_messages(join => ', ', join_all => ', ');
    $Monitoring::GLPlugin::plugin->nagios_exit($code, $message);
  }
}

sub check_snmp_and_model {
  my $self = shift;
  $Monitoring::GLPlugin::SNMP::mibs_and_oids->{'MIB-II'} = {
    sysDescr => '1.3.6.1.2.1.1.1',
    sysObjectID => '1.3.6.1.2.1.1.2',
    sysUpTime => '1.3.6.1.2.1.1.3',
    sysName => '1.3.6.1.2.1.1.5',
  };
  $Monitoring::GLPlugin::SNMP::mibs_and_oids->{'SNMP-FRAMEWORK-MIB'} = {
    snmpEngineID => '1.3.6.1.6.3.10.2.1.1.0',
    snmpEngineBoots => '1.3.6.1.6.3.10.2.1.2.0',
    snmpEngineTime => '1.3.6.1.6.3.10.2.1.3.0',
    snmpEngineMaxMessageSize => '1.3.6.1.6.3.10.2.1.4.0',
  };
  if ($self->opts->snmpwalk) {
    my $response = {};
    if (! -f $self->opts->snmpwalk) {
      $self->add_message(CRITICAL, 
          sprintf 'file %s not found',
          $self->opts->snmpwalk);
    } elsif (-x $self->opts->snmpwalk) {
      my $cmd = sprintf "%s -ObentU -v%s -c%s %s 1.3.6.1.4.1 2>&1",
          $self->opts->snmpwalk,
          $self->opts->protocol,
          $self->opts->community,
          $self->opts->hostname;
      open(WALK, "$cmd |");
      while (<WALK>) {
        if (/^([\.\d]+) = .*?: (\-*\d+)/) {
          $response->{$1} = $2;
        } elsif (/^([\.\d]+) = .*?: "(.*?)"/) {
          $response->{$1} = $2;
          $response->{$1} =~ s/\s+$//;
        }
      }
      close WALK;
    } else {
      if (defined $self->opts->offline && $self->opts->mode ne 'walk') {
        if ((time - (stat($self->opts->snmpwalk))[9]) > $self->opts->offline) {
          $self->add_message(UNKNOWN,
              sprintf 'snmpwalk file %s is too old', $self->opts->snmpwalk);
        }
      }
      $self->opts->override_opt('hostname', 'walkhost') if $self->opts->mode ne 'walk';
      open(MESS, $self->opts->snmpwalk);
      while(<MESS>) {
        # SNMPv2-SMI::enterprises.232.6.2.6.7.1.3.1.4 = INTEGER: 6
        if (/^([\d\.]+) = .*?INTEGER: .*\((\-*\d+)\)/) {
          # .1.3.6.1.2.1.2.2.1.8.1 = INTEGER: down(2)
          $response->{$1} = $2;
        } elsif (/^([\d\.]+) = .*?Opaque:.*?Float:.*?([\-\.\d]+)/) {
          # .1.3.6.1.4.1.2021.10.1.6.1 = Opaque: Float: 0.938965
          $response->{$1} = $2;
        } elsif (/^([\d\.]+) = STRING:\s*$/) {
          $response->{$1} = "";
        } elsif (/^([\d\.]+) = Network Address: (.*)/) {
          $response->{$1} = $2;
        } elsif (/^([\d\.]+) = Hex-STRING: (.*)/) {
          $response->{$1} = "0x".$2;
          $response->{$1} =~ s/\s+$//;
        } elsif (/^([\d\.]+) = \w+: (\-*\d+)\s*$/) {
          $response->{$1} = $2;
        } elsif (/^([\d\.]+) = \w+: "(.*?)"/) {
          $response->{$1} = $2;
          $response->{$1} =~ s/\s+$//;
        } elsif (/^([\d\.]+) = \w+: (.*)/) {
          $response->{$1} = $2;
          $response->{$1} =~ s/\s+$//;
        } elsif (/^([\d\.]+) = (\-*\d+)/) {
          $response->{$1} = $2;
        } elsif (/^([\d\.]+) = "(.*?)"/) {
          $response->{$1} = $2;
          $response->{$1} =~ s/\s+$//;
        }
      }
      close MESS;
    }
    foreach my $oid (keys %$response) {
      if ($oid =~ /^\./) {
        my $nodot = $oid;
        $nodot =~ s/^\.//g;
        $response->{$nodot} = $response->{$oid};
        delete $response->{$oid};
      }
    }
    map { $response->{$_} =~ s/^\s+//; $response->{$_} =~ s/\s+$//; }
        keys %$response;
    $self->set_rawdata($response);
  } else {
    $self->establish_snmp_session();
  }
  if (! $self->check_messages()) {
    my $tic = time;
    my $sysUptime = $self->get_snmp_object('MIB-II', 'sysUpTime', 0);
    my $snmpEngineTime = $self->get_snmp_object('SNMP-FRAMEWORK-MIB', 'snmpEngineTime');
    my $sysDescr = $self->get_snmp_object('MIB-II', 'sysDescr', 0);
    my $tac = time;
    if (defined $sysUptime && defined $sysDescr) {
      # drecksschrott asa liefert negative werte
      # und drecksschrott socomec liefert: wrong type (should be INTEGER): NULL
      if (defined $snmpEngineTime && $snmpEngineTime =~ /^\d+$/ && $snmpEngineTime > 0) {
        $self->{uptime} = $snmpEngineTime;
      } else {
        $self->{uptime} = $self->timeticks($sysUptime);
      }
      $self->{productname} = $sysDescr;
      $self->{sysobjectid} = $self->get_snmp_object('MIB-II', 'sysObjectID', 0);
      $self->debug(sprintf 'uptime: %s', $self->{uptime});
      $self->debug(sprintf 'up since: %s',
          scalar localtime (time - $self->{uptime}));
      $Monitoring::GLPlugin::SNMP::uptime = $self->{uptime};
      $self->debug('whoami: '.$self->{productname});
    } else {
      if ($tac - $tic >= $Monitoring::GLPlugin::SNMP::session->timeout) {
        $self->add_message(UNKNOWN,
            'could not contact snmp agent, timeout during snmp-get sysUptime');
      } else {
        $self->add_message(UNKNOWN,
            'got neither sysUptime nor sysDescr, is this snmp agent working correctly?');
      }
      $Monitoring::GLPlugin::SNMP::session->close if $Monitoring::GLPlugin::SNMP::session;
    }
  }
}

sub establish_snmp_session {
  my $self = shift;
  $self->set_timeout_alarm();
  if (eval "require Net::SNMP") {
    my %params = ();
    my $net_snmp_version = Net::SNMP->VERSION(); # 5.002000 or 6.000000
    $params{'-translate'} = [ # because we see "NULL" coming from socomec devices
      -all => 0x0,
      -nosuchobject => 1,
      -nosuchinstance => 1,
      -endofmibview => 1,
      -unsigned => 1,
    ];
    $params{'-hostname'} = $self->opts->hostname;
    $params{'-version'} = $self->opts->protocol;
    if ($self->opts->port) {
      $params{'-port'} = $self->opts->port;
    }
    if ($self->opts->domain) {
      $params{'-domain'} = $self->opts->domain;
    }
    $self->v2tov3;
    if ($self->opts->protocol eq '3') {
      $params{'-version'} = $self->opts->protocol;
      $params{'-username'} = $self->opts->username;
      if ($self->opts->authpassword) {
        $params{'-authpassword'} = 
            $self->decode_password($self->opts->authpassword);
      }
      if ($self->opts->authprotocol) {
        $params{'-authprotocol'} = $self->opts->authprotocol;
      }
      if ($self->opts->privpassword) {
        $params{'-privpassword'} = 
            $self->decode_password($self->opts->privpassword);
      }
      if ($self->opts->privprotocol) {
        $params{'-privprotocol'} = $self->opts->privprotocol;
      }
      # context hat in der session nix verloren, sondern wird
      # als zusatzinfo bei den requests mitgeschickt
      #if ($self->opts->contextengineid) {
      #  $params{'-contextengineid'} = $self->opts->contextengineid;
      #}
      #if ($self->opts->contextname) {
      #  $params{'-contextname'} = $self->opts->contextname;
      #}
    } else {
      $params{'-community'} = 
          $self->decode_password($self->opts->community);
    }
    my ($session, $error) = Net::SNMP->session(%params);
    if (! defined $session) {
      $self->add_message(CRITICAL, 
          sprintf 'cannot create session object: %s', $error);
      $self->debug(Data::Dumper::Dumper(\%params));
    } else {
      my $max_msg_size = $session->max_msg_size();
      $session->max_msg_size(4 * $max_msg_size);
      $Monitoring::GLPlugin::SNMP::session = $session;
    }
  } else {
    $self->add_message(CRITICAL,
        'could not find Net::SNMP module');
  }
}

sub establish_snmp_secondary_session {
  my $self = shift;
  if ($self->opts->protocol eq '3') {
  } else {
    if (defined $self->opts->community2 &&
        $self->decode_password($self->opts->community2) ne
        $self->decode_password($self->opts->community)) {
      $Monitoring::GLPlugin::SNMP::session = undef;
      $self->opts->override_opt('community',
        $self->decode_password($self->opts->community2)) ;
      $self->establish_snmp_session;
    }
  }
}

sub mult_snmp_max_msg_size {
  my $self = shift;
  my $factor = shift || 10;
  $self->debug(sprintf "raise maxmsgsize %d * %d", 
      $factor, $Monitoring::GLPlugin::SNMP::session->max_msg_size()) if $Monitoring::GLPlugin::SNMP::session;
  $Monitoring::GLPlugin::SNMP::session->max_msg_size($factor * $Monitoring::GLPlugin::SNMP::session->max_msg_size()) if $Monitoring::GLPlugin::SNMP::session;
}

sub no_such_model {
  my $self = shift;
  printf "Model %s is not implemented\n", $self->{productname};
  exit 3;
}

sub no_such_mode {
  my $self = shift;
  if (ref($self) eq "Classes::Generic") {
    $self->init();
  } elsif (ref($self) eq "Classes::Device") {
    $self->add_message(UNKNOWN, 'the device did not implement the mibs this plugin is asking for');
    $self->add_message(UNKNOWN,
        sprintf('unknown device%s', $self->{productname} eq 'unknown' ?
            '' : '('.$self->{productname}.')'));
  } elsif (ref($self) eq "Monitoring::GLPlugin::SNMP") {
    # uptime, offline
    $self->init();
  } else {
    eval {
      bless $self, "Classes::Generic";
      $self->init();
    };
    if ($@) {
      bless $self, "Monitoring::GLPlugin::SNMP";
      $self->init();
    }
  }
  if (ref($self) eq "Monitoring::GLPlugin::SNMP") {
    printf "Mode %s is not implemented for this type of device\n",
        $self->opts->mode;
    exit 3;
  }
}

sub uptime {
  my $self = shift;
  return $Monitoring::GLPlugin::SNMP::uptime;
}

sub discover_suitable_class {
  my $self = shift;
  my $sysobj = $self->get_snmp_object('MIB-II', 'sysObjectID', 0);
  if ($sysobj && exists $Monitoring::GLPlugin::SNMP::discover_ids->{$sysobj}) {
    return $Monitoring::GLPlugin::SNMP::discover_ids->{$sysobj};
  }
}

sub implements_mib {
  my $self = shift;
  my $mib = shift;
  if (! exists $Monitoring::GLPlugin::SNMP::mib_ids->{$mib}) {
    return 0;
  }
  my $sysobj = $self->get_snmp_object('MIB-II', 'sysObjectID', 0);
  $sysobj =~ s/^\.// if $sysobj;
  if ($sysobj && $sysobj eq $Monitoring::GLPlugin::SNMP::mib_ids->{$mib}) {
    $self->debug(sprintf "implements %s (sysobj exact)", $mib);
    return 1;
  }
  if ($Monitoring::GLPlugin::SNMP::mib_ids->{$mib} eq
      substr $sysobj, 0, length $Monitoring::GLPlugin::SNMP::mib_ids->{$mib}) {
    $self->debug(sprintf "implements %s (sysobj)", $mib);
    return 1;
  }
  # some mibs are only composed of tables
  my $traces;
  if ($self->opts->snmpwalk) {
    $traces = {@{[map {
        $_, $self->rawdata->{$_} 
    } grep {
        substr($_, 0, length($Monitoring::GLPlugin::SNMP::mib_ids->{$mib})) eq $Monitoring::GLPlugin::SNMP::mib_ids->{$mib} 
    } keys %{$self->rawdata}]}};
  } else {
    my %params = (
        -varbindlist => [
            $Monitoring::GLPlugin::SNMP::mib_ids->{$mib}
        ]
    );
    if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
      $params{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
      $params{-contextname} = $self->opts->contextname if $self->opts->contextname;
    }
    $traces = $Monitoring::GLPlugin::SNMP::session->get_next_request(%params);
  }
  if ($traces && # must find oids following to the ident-oid
      ! exists $traces->{$Monitoring::GLPlugin::SNMP::mib_ids->{$mib}} && # must not be the ident-oid
      grep { # following oid is inside this tree
          substr($_, 0, length($Monitoring::GLPlugin::SNMP::mib_ids->{$mib})) eq $Monitoring::GLPlugin::SNMP::mib_ids->{$mib};
      } keys %{$traces}) {
    $self->debug(sprintf "implements %s (found traces)", $mib);
    return 1;
  }
}

sub timeticks {
  my $self = shift;
  my $timestr = shift;
  if ($timestr =~ /\((\d+)\)/) {
    # Timeticks: (20718727) 2 days, 9:33:07.27
    $timestr = $1 / 100;
  } elsif ($timestr =~ /(\d+)\s*day[s]*.*?(\d+):(\d+):(\d+)\.(\d+)/) {
    # Timeticks: 2 days, 9:33:07.27
    $timestr = $1 * 24 * 3600 + $2 * 3600 + $3 * 60 + $4;
  } elsif ($timestr =~ /(\d+):(\d+):(\d+):(\d+)\.(\d+)/) {
    # Timeticks: 0001:03:18:42.77
    $timestr = $1 * 3600 * 24 + $2 * 3600 + $3 * 60 + $4;
  } elsif ($timestr =~ /(\d+):(\d+):(\d+)\.(\d+)/) {
    # Timeticks: 9:33:07.27
    $timestr = $1 * 3600 + $2 * 60 + $3;
  } elsif ($timestr =~ /(\d+)\s*hour[s]*.*?(\d+):(\d+)\.(\d+)/) {
    # Timeticks: 3 hours, 42:17.98
    $timestr = $1 * 3600 + $2 * 60 + $3;
  } elsif ($timestr =~ /(\d+)\s*minute[s]*.*?(\d+)\.(\d+)/) {
    # Timeticks: 36 minutes, 01.96
    $timestr = $1 * 60 + $2;
  } elsif ($timestr =~ /(\d+)\.\d+\s*second[s]/) {
    # Timeticks: 01.02 seconds
    $timestr = $1;
  } elsif ($timestr =~ /^(\d+)$/) {
    $timestr = $1 / 100;
  }
  return $timestr;
}

sub human_timeticks {
  my $self = shift;
  my $timeticks = shift;
  my $days = int($timeticks / 86400);
  $timeticks -= ($days * 86400);
  my $hours = int($timeticks / 3600);
  $timeticks -= ($hours * 3600);
  my $minutes = int($timeticks / 60);
  my $seconds = $timeticks % 60;
  $days = $days < 1 ? '' : $days .'d ';
  return $days . sprintf "%dh %dm %ds", $hours, $minutes, $seconds;
}

sub internal_name {
  my $self = shift;
  my $class = ref($self);
  $class =~ s/^.*:://;
  if (exists $self->{flat_indices}) {
    return sprintf "%s_%s", uc $class, $self->{flat_indices};
  } else {
    return sprintf "%s", uc $class;
  }
}

################################################################
# file-related functions
#
sub create_interface_cache_file {
  my $self = shift;
  my $extension = "";
  if ($self->opts->snmpwalk && ! $self->opts->hostname) {
    $self->opts->override_opt('hostname',
        'snmpwalk.file'.md5_hex($self->opts->snmpwalk))
  }
  if ($self->opts->community) { 
    $extension .= md5_hex($self->opts->community);
  }
  $extension =~ s/\//_/g;
  $extension =~ s/\(/_/g;
  $extension =~ s/\)/_/g;
  $extension =~ s/\*/_/g;
  $extension =~ s/\s/_/g;
  return sprintf "%s/%s_interface_cache_%s", $self->statefilesdir(),
      $self->opts->hostname, lc $extension;
}

sub create_entry_cache_file {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  return lc sprintf "%s_%s_%s_%s_cache",
      $self->create_interface_cache_file(),
      $mib, $table, join('#', @{$key_attr});
}

sub update_entry_cache {
  my $self = shift;
  my $force = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  if (ref($key_attr) ne "ARRAY") {
    $key_attr = [$key_attr];
  }
  my $cache = sprintf "%s_%s_%s_cache", 
      $mib, $table, join('#', @{$key_attr});
  my $statefile = $self->create_entry_cache_file($mib, $table, $key_attr);
  my $update = time - 3600;
  #my $update = time - 1;
  if ($force || ! -f $statefile || ((stat $statefile)[9]) < ($update)) {
    $self->debug(sprintf 'force update of %s %s %s %s cache',
        $self->opts->hostname, $self->opts->mode, $mib, $table);
    $self->{$cache} = {};
    foreach my $entry ($self->get_snmp_table_objects($mib, $table)) {
      my $key = join('#', map { $entry->{$_} } @{$key_attr});
      my $hash = $key . '-//-' . join('.', @{$entry->{indices}});
      $self->{$cache}->{$hash} = $entry->{indices};
    }
    $self->save_cache($mib, $table, $key_attr);
  }
  $self->load_cache($mib, $table, $key_attr);
}

sub save_cache {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  if (ref($key_attr) ne "ARRAY") {
    $key_attr = [$key_attr];
  }
  my $cache = sprintf "%s_%s_%s_cache", 
      $mib, $table, join('#', @{$key_attr});
  $self->create_statefilesdir();
  my $statefile = $self->create_entry_cache_file($mib, $table, $key_attr);
  open(STATE, ">".$statefile.".".$$);
  printf STATE Data::Dumper::Dumper($self->{$cache});
  close STATE;
  rename $statefile.".".$$, $statefile;
  $self->debug(sprintf "saved %s to %s",
      Data::Dumper::Dumper($self->{$cache}), $statefile);
}

sub load_cache {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  if (ref($key_attr) ne "ARRAY") {
    $key_attr = [$key_attr];
  }
  my $cache = sprintf "%s_%s_%s_cache", 
      $mib, $table, join('#', @{$key_attr});
  my $statefile = $self->create_entry_cache_file($mib, $table, $key_attr);
  $self->{$cache} = {};
  if ( -f $statefile) {
    our $VAR1;
    our $VAR2;
    eval {
      require $statefile;
    };
    if($@) {
      printf "rumms\n";
    }
    # keinesfalls mehr require verwenden!!!!!!
    # beim require enthaelt VAR1 andere werte als beim slurp
    # und zwar diejenigen, die beim letzten save_cache geschrieben wurden.
    my $content = do { local (@ARGV, $/) = $statefile; my $x = <>; close ARGV; $x };
    $VAR1 = eval "$content";
    $self->debug(sprintf "load %s", Data::Dumper::Dumper($VAR1));
    $self->{$cache} = $VAR1;
  }
}


################################################################
# top-level convenience functions
#
sub get_snmp_objects {
  my $self = shift;
  my $mib = shift;
  my @mos = @_;
  foreach (@mos) {
    my $value = $self->get_snmp_object($mib, $_, 0);
    if (defined $value) {
      $self->{$_} = $value;
    } else {
      my $value = $self->get_snmp_object($mib, $_);
      if (defined $value) {
        $self->{$_} = $value;
      }
    }
  }
}

sub get_snmp_tables {
  my $self = shift;
  my $mib = shift;
  my $infos = shift;
  foreach my $info (@{$infos}) {
    my $arrayname = $info->[0];
    my $table = $info->[1];
    my $class = $info->[2];
    my $filter = $info->[3];
    $self->{$arrayname} = [] if ! exists $self->{$arrayname};
    if (! exists $Monitoring::GLPlugin::SNMP::tablecache->{$mib} || ! exists $Monitoring::GLPlugin::SNMP::tablecache->{$mib}->{$table}) {
      $Monitoring::GLPlugin::SNMP::tablecache->{$mib}->{$table} = [];
      foreach ($self->get_snmp_table_objects($mib, $table)) {
        my $new_object = $class->new(%{$_});
        next if (defined $filter && ! &$filter($new_object));
        push(@{$self->{$arrayname}}, $new_object);
        push(@{$Monitoring::GLPlugin::SNMP::tablecache->{$mib}->{$table}}, $new_object);
      }
    } else {
      $self->debug(sprintf "get_snmp_tables %s %s cache hit", $mib, $table);
      foreach (@{$Monitoring::GLPlugin::SNMP::tablecache->{$mib}->{$table}}) {
        push(@{$self->{$arrayname}}, $_);
      }
    }
  }
}

sub mibs_and_oids_definition {
  my $self = shift;
  my $mib = shift;
  my $definition = shift;
  my @values = @_;
  if (exists $Monitoring::GLPlugin::SNMP::definitions->{$mib} &&
      exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}) {
    if (ref($Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}) eq "CODE") {
      return $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->(@values);
    } elsif (ref($Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}) eq "HASH") {
      return $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->{$values[0]};
    }
  } else {
    return "unknown_".$definition;
  }
}

################################################################
# 2nd level 
#
sub get_snmp_object {
  my $self = shift;
  my $mib = shift;
  my $mo = shift;
  my $index = shift;
  if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib} &&
      exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$mo}) {
    my $oid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$mo}.
        (defined $index ? '.'.$index : '');
    my $response = $self->get_request(-varbindlist => [$oid]);
    if (defined $response->{$oid}) {
      if ($response->{$oid} eq 'noSuchInstance' || $response->{$oid} eq 'noSuchObject') {
        $response->{$oid} = undef;
      } elsif (my @symbols = $self->make_symbolic($mib, $response, [[$index]])) {
        $response->{$oid} = $symbols[0]->{$mo};
      }
    }
    $self->debug(sprintf "GET: %s::%s (%s) : %s", $mib, $mo, $oid, defined $response->{$oid} ? $response->{$oid} : "<undef>");
    return $response->{$oid};
  }
  return undef;
}

sub get_snmp_table_objects_with_cache {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  #return $self->get_snmp_table_objects($mib, $table);
  $self->update_entry_cache(0, $mib, $table, $key_attr);
  my @indices = $self->get_cache_indices($mib, $table, $key_attr);
  my @entries = ();
  foreach ($self->get_snmp_table_objects($mib, $table, \@indices)) {
    push(@entries, $_);
  }
  return @entries;
}

# get_snmp_table_objects('MIB-Name', 'Table-Name', 'Table-Entry', [indices])
# returns array of hashrefs
sub get_snmp_table_objects {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $indices = shift || [];
  my @entries = ();
  my $augmenting_table;
  $self->debug(sprintf "get_snmp_table_objects %s %s", $mib, $table);
  if ($table =~ /^(.*?)\+(.*)/) {
    $table = $1;
    $augmenting_table = $2;
  }
  my $entry = $table;
  $entry =~ s/Table/Entry/g;
  if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib} &&
      exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$table}) {
    if (scalar(@{$indices}) == 1 && $indices->[0] == -1) {
      # get mini-version of a table
      my $result = {};
      my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
      my $eoidlen = length($eoid);
      my @columns = map {
          $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
      } grep {
        substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq
            $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.'
      } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
      my $ifresult = $self->get_entries(
          -columns => \@columns,
      );
      map { $result->{$_} = $ifresult->{$_} }
          keys %{$ifresult};
      if ($augmenting_table &&
          exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$augmenting_table}) {
        my $entry = $augmenting_table;
        $entry =~ s/Table/Entry/g;
        my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
        my $eoidlen = length($eoid);
        my @columns = map {
            $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
        } grep {
          substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq $eoid
        } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
        my $ifresult = $self->get_entries(
            -columns => \@columns,
        );
        map { $result->{$_} = $ifresult->{$_} }
            keys %{$ifresult};
      }
      my @indices = 
          $self->get_indices(
              -baseoid => $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry},
              -oids => [keys %{$result}]);
      $self->debug(sprintf "get_snmp_table_objects get_table returns %d indices",
          scalar(@indices));
      @entries = $self->make_symbolic($mib, $result, \@indices);
      @entries = map { $_->{indices} = shift @indices; $_ } @entries;
    } elsif (scalar(@{$indices}) == 1) {
      my $result = {};
      my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
      my $eoidlen = length($eoid);
      my @columns = map {
          $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
      } grep {
        substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq
            $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.'
      } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
      my $index = join('.', @{$indices->[0]});
      my $ifresult = $self->get_entries(
          -startindex => $index,
          -endindex => $index,
          -columns => \@columns,
      );
      map { $result->{$_} = $ifresult->{$_} }
          keys %{$ifresult};
      if ($augmenting_table &&
          exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$augmenting_table}) {
        my $entry = $augmenting_table;
        $entry =~ s/Table/Entry/g;
        my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
        my $eoidlen = length($eoid);
        my @columns = map {
            $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
        } grep {
          substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq $eoid
        } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
        my $ifresult = $self->get_entries(
            -startindex => $index,
            -endindex => $index,
            -columns => \@columns,
        );
        map { $result->{$_} = $ifresult->{$_} }
            keys %{$ifresult};
      }
      @entries = $self->make_symbolic($mib, $result, $indices);
      @entries = map { $_->{indices} = shift @{$indices}; $_ } @entries;
    } elsif (scalar(@{$indices}) > 1) {
    # man koennte hier pruefen, ob die indices aufeinanderfolgen
    # und dann get_entries statt get_table aufrufen
      my $result = {};
      my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
      my $eoidlen = length($eoid);
      my @columns = map {
          $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
      } grep {
        substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq $eoid
      } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
      my @sortedindices = map { $_->[0] }
          sort { $a->[1] cmp $b->[1] }
              map { [$_,
                  join '', map { sprintf("%30d",$_) } split( /\./, $_)
              ] } map { join('.', @{$_})} @{$indices};
      my $startindex = $sortedindices[0];
      my $endindex = $sortedindices[$#sortedindices];
      if (0) {
        # holzweg. dicke ciscos liefern unvollstaendiges resultat, d.h.
        # bei 138,19,157 kommt nur 138..144, dann ist schluss.
        # maxrepetitions bringt nichts.
        $result = $self->get_entries(
            -startindex => $startindex,
            -endindex => $endindex,
            -columns => \@columns,
        );
      } else {
        foreach my $ifidx (@sortedindices) {
          my $ifresult = $self->get_entries(
              -startindex => $ifidx,
              -endindex => $ifidx,
              -columns => \@columns,
          );
          map { $result->{$_} = $ifresult->{$_} }
              keys %{$ifresult};
        }
      }
      if ($augmenting_table &&
          exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$augmenting_table}) {
        my $entry = $augmenting_table;
        $entry =~ s/Table/Entry/g;
        my $eoid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry}.'.';
        my $eoidlen = length($eoid);
        my @columns = map {
            $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}
        } grep {
          substr($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$_}, 0, $eoidlen) eq $eoid
        } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}};
        foreach my $ifidx (@sortedindices) {
          my $ifresult = $self->get_entries(
              -startindex => $ifidx,
              -endindex => $ifidx,
              -columns => \@columns,
          );
          map { $result->{$_} = $ifresult->{$_} }
              keys %{$ifresult};
        }
      }
      # now we have numerical_oid+index => value
      # needs to become symboic_oid => value
      #my @indices =
      # $self->get_indices($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry});
      @entries = $self->make_symbolic($mib, $result, $indices);
      @entries = map { $_->{indices} = shift @{$indices}; $_ } @entries;
    } else {
      $self->debug(sprintf "get_snmp_table_objects calls get_table %s",
          $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$table});
      my $result = $self->get_table(
          -baseoid => $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$table});
      $self->debug(sprintf "get_snmp_table_objects get_table returns %d oids",
          scalar(keys %{$result}));
      # now we have numerical_oid+index => value
      # needs to become symboic_oid => value
      my @indices = 
          $self->get_indices(
              -baseoid => $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$entry},
              -oids => [keys %{$result}]);
      $self->debug(sprintf "get_snmp_table_objects get_table returns %d indices",
          scalar(@indices));
      @entries = $self->make_symbolic($mib, $result, \@indices);
      @entries = map { $_->{indices} = shift @indices; $_ } @entries;
    }
  }
  @entries = map { $_->{flat_indices} = join(".", @{$_->{indices}}); $_ } @entries;
  return @entries;
}

################################################################
# 3rd level functions. calling net::snmp-functions
# 
sub get_request {
  my $self = shift;
  my %params = @_;
  my @notcached = ();
  foreach my $oid (@{$params{'-varbindlist'}}) {
    $self->add_oidtrace($oid);
    if (! exists $Monitoring::GLPlugin::SNMP::rawdata->{$oid}) {
      push(@notcached, $oid);
    }
  }
  if (! $self->opts->snmpwalk && (scalar(@notcached) > 0)) {
    my %params = ();
    if ($Monitoring::GLPlugin::SNMP::session->version() == 0) {
      $params{-varbindlist} = \@notcached;
    } elsif ($Monitoring::GLPlugin::SNMP::session->version() == 1) {
      $params{-varbindlist} = \@notcached;
      #$params{-nonrepeaters} = scalar(@notcached);
    } elsif ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
      $params{-varbindlist} = \@notcached;
      $params{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
      $params{-contextname} = $self->opts->contextname if $self->opts->contextname;
    }
    my $result = $Monitoring::GLPlugin::SNMP::session->get_request(%params);
    foreach my $key (%{$result}) {
      $self->add_rawdata($key, $result->{$key});
    }
  }
  my $result = {};
  map { $result->{$_} = $Monitoring::GLPlugin::SNMP::rawdata->{$_} }
      @{$params{'-varbindlist'}};
  return $result;
}

sub get_entries_get_bulk {
  my $self = shift;
  my %params = @_;
  my $result = {};
  $self->debug(sprintf "get_entries_get_bulk %s", Data::Dumper::Dumper(\%params));
  my %newparams = ();
  $newparams{'-maxrepetitions'} = 3;
  $newparams{'-startindex'} = $params{'-startindex'}
      if defined $params{'-startindex'};
  $newparams{'-endindex'} = $params{'-endindex'}
      if defined $params{'-endindex'};
  $newparams{'-columns'} = $params{'-columns'};
  if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
    $newparams{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
    $newparams{-contextname} = $self->opts->contextname if $self->opts->contextname;
  }
  $result = $Monitoring::GLPlugin::SNMP::session->get_entries(%newparams);
  return $result;
}

sub get_entries_get_next {
  my $self = shift;
  my %params = @_;
  my $result = {};
  $self->debug(sprintf "get_entries_get_next %s", Data::Dumper::Dumper(\%params));
  my %newparams = ();
  $newparams{'-maxrepetitions'} = 0;
  $newparams{'-startindex'} = $params{'-startindex'}
      if defined $params{'-startindex'};
  $newparams{'-endindex'} = $params{'-endindex'}
      if defined $params{'-endindex'};
  $newparams{'-columns'} = $params{'-columns'};
  if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
    $newparams{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
    $newparams{-contextname} = $self->opts->contextname if $self->opts->contextname;
  }
  $result = $Monitoring::GLPlugin::SNMP::session->get_entries(%newparams);
  return $result;
}

sub get_entries_get_next_1index {
  my $self = shift;
  my %params = @_;
  my $result = {};
  $self->debug(sprintf "get_entries_get_next_1index %s", Data::Dumper::Dumper(\%params));
  my %newparams = ();
  $newparams{'-startindex'} = $params{'-startindex'}
      if defined $params{'-startindex'};
  $newparams{'-endindex'} = $params{'-endindex'}
      if defined $params{'-endindex'};
  $newparams{'-columns'} = $params{'-columns'};
  my %singleparams = ();
  $singleparams{'-maxrepetitions'} = 0;
  if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
    $singleparams{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
    $singleparams{-contextname} = $self->opts->contextname if $self->opts->contextname;
  }
  foreach my $index ($newparams{'-startindex'}..$newparams{'-endindex'}) {
    foreach my $oid (@{$newparams{'-columns'}}) {
      $singleparams{'-columns'} = [$oid];
      $singleparams{'-startindex'} = $index;
      $singleparams{'-endindex'} =$index;
      my $singleresult = $Monitoring::GLPlugin::SNMP::session->get_entries(%singleparams);
      foreach my $key (keys %{$singleresult}) {
        $result->{$key} = $singleresult->{$key};
      }
    }
  }
  return $result;
}

sub get_entries_get_simple {
  my $self = shift;
  my %params = @_;
  my $result = {};
  $self->debug(sprintf "get_entries_get_simple %s", Data::Dumper::Dumper(\%params));
  my %newparams = ();
  $newparams{'-startindex'} = $params{'-startindex'}
      if defined $params{'-startindex'};
  $newparams{'-endindex'} = $params{'-endindex'}
      if defined $params{'-endindex'};
  $newparams{'-columns'} = $params{'-columns'};
  my %singleparams = ();
  if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
    $singleparams{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
    $singleparams{-contextname} = $self->opts->contextname if $self->opts->contextname;
  }
  foreach my $index ($newparams{'-startindex'}..$newparams{'-endindex'}) {
    foreach my $oid (@{$newparams{'-columns'}}) {
      $singleparams{'-varbindlist'} = [$oid.".".$index];
      my $singleresult = $Monitoring::GLPlugin::SNMP::session->get_request(%singleparams);
      foreach my $key (keys %{$singleresult}) {
        $result->{$key} = $singleresult->{$key};
      }
    }
  }
  return $result;
}

sub get_entries {
  my $self = shift;
  my %params = @_;
  # [-startindex]
  # [-endindex]
  # -columns
  my $result = {};
  $self->debug(sprintf "get_entries %s", Data::Dumper::Dumper(\%params));
  if (! $self->opts->snmpwalk) {
    $result = $self->get_entries_get_bulk(%params);
    if (! $result) {
      if (scalar (@{$params{'-columns'}}) < 50 && $params{'-endindex'} && $params{'-startindex'} eq $params{'-endindex'}) {
        $result = $self->get_entries_get_simple(%params);
      } else {
        $result = $self->get_entries_get_next(%params);
      }
      if (! $result && defined $params{'-startindex'} && $params{'-startindex'} !~ /\./) {
        # compound indexes cannot continue, as these two methods iterate numerically
        if ($Monitoring::GLPlugin::SNMP::session->error() =~ /tooBig/i) {
          $result = $self->get_entries_get_next_1index(%params);
        }
        if (! $result) {
          $result = $self->get_entries_get_simple(%params);
        }
        if (! $result) {
          $self->debug(sprintf "nutzt nix\n");
        }
      }
    }
    foreach my $key (keys %{$result}) {
      if (substr($key, -1) eq " ") {
        my $value = $result->{$key};
        delete $result->{$key};
        $key =~ s/\s+$//g;
        $result->{$key} = $value;
        #
        # warum?
        #
        # %newparams ist:
        #  '-columns' => [
        #                  '1.3.6.1.2.1.2.2.1.8',
        #                  '1.3.6.1.2.1.2.2.1.13',
        #                  ...
        #                  '1.3.6.1.2.1.2.2.1.16'
        #                ],
        #  '-startindex' => '2',
        #  '-endindex' => '2'
        #
        # und $result ist:
        #  ...
        #  '1.3.6.1.2.1.2.2.1.2.2' => 'Adaptive Security Appliance \'outside\' interface',
        #  '1.3.6.1.2.1.2.2.1.16.2 ' => 4281465004,
        #  '1.3.6.1.2.1.2.2.1.13.2' => 0,
        #  ...
        #
        # stinkstiefel!
        #
      }
      $self->add_rawdata($key, $result->{$key});
    }
  } else {
    my $preresult = $self->get_matching_oids(
        -columns => $params{'-columns'});
    foreach (keys %{$preresult}) {
      $result->{$_} = $preresult->{$_};
    }
    my @sortedkeys = map { $_->[0] }
        sort { $a->[1] cmp $b->[1] }
            map { [$_,
                    join '', map { sprintf("%30d",$_) } split( /\./, $_)
                  ] } keys %{$result};
    my @to_del = ();
    if ($params{'-startindex'}) {
      foreach my $resoid (@sortedkeys) {
        foreach my $oid (@{$params{'-columns'}}) {
          my $poid = $oid.'.';
          my $lpoid = length($poid);
          if (substr($resoid, 0, $lpoid) eq $poid) {
            my $oidpattern = $poid;
            $oidpattern =~ s/\./\\./g;
            if ($resoid =~ /^$oidpattern(.+)$/) {
              if ($1 lt $params{'-startindex'}) {
                push(@to_del, $oid.'.'.$1);
              }
            }
          }
        }
      }
    }
    if ($params{'-endindex'}) {
      foreach my $resoid (@sortedkeys) {
        foreach my $oid (@{$params{'-columns'}}) {
          my $poid = $oid.'.';
          my $lpoid = length($poid);
          if (substr($resoid, 0, $lpoid) eq $poid) {
            my $oidpattern = $poid;
            $oidpattern =~ s/\./\\./g;
            if ($resoid =~ /^$oidpattern(.+)$/) {
              if ($1 gt $params{'-endindex'}) {
                push(@to_del, $oid.'.'.$1);
              }
            }
          }
        }
      }
    }
    foreach (@to_del) {
      delete $result->{$_};
    }
  }
  return $result;
}

sub get_entries_by_walk {
  my $self = shift;
  my %params = @_;
  if (! $self->opts->snmpwalk) {
    $self->add_ok("if you get this crap working correctly, let me know");
    if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
      $params{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
      $params{-contextname} = $self->opts->contextname if $self->opts->contextname;
    }
    $self->debug(sprintf "get_tree %s", Data::Dumper::Dumper(\%params));
    my @baseoids = @{$params{-varbindlist}};
    delete $params{-varbindlist};
    if ($Monitoring::GLPlugin::SNMP::session->version() == 0) {
      foreach my $baseoid (@baseoids) {
        $params{-varbindlist} = [$baseoid];
        while (my $result = $Monitoring::GLPlugin::SNMP::session->get_next_request(%params)) {
          $params{-varbindlist} = [($Monitoring::GLPlugin::SNMP::session->var_bind_names)[0]];
        }
      }
    } else {
      $params{-maxrepetitions} = 200;
      foreach my $baseoid (@baseoids) {
        $params{-varbindlist} = [$baseoid];
        while (my $result = $Monitoring::GLPlugin::SNMP::session->get_bulk_request(%params)) {
          my @names = $Monitoring::GLPlugin::SNMP::session->var_bind_names();
          my @oids = $self->sort_oids(\@names);
          $params{-varbindlist} = [pop @oids];
        }
      }
    }
  } else {
    return $self->get_matching_oids(
        -columns => $params{-varbindlist});
  }
}

sub get_table {
  my $self = shift;
  my %params = @_;
  $self->add_oidtrace($params{'-baseoid'});
  if (! $self->opts->snmpwalk) {
    my @notcached = ();
    if ($Monitoring::GLPlugin::SNMP::session->version() == 3) {
      $params{-contextengineid} = $self->opts->contextengineid if $self->opts->contextengineid;
      $params{-contextname} = $self->opts->contextname if $self->opts->contextname;
    }
    $self->debug(sprintf "get_table %s", Data::Dumper::Dumper(\%params));
    my $result = $Monitoring::GLPlugin::SNMP::session->get_table(%params);
    $self->debug(sprintf "get_table returned %d oids", scalar(keys %{$result}));
    if (scalar(keys %{$result}) == 0) {
      $self->debug(sprintf "get_table error: %s", 
          $Monitoring::GLPlugin::SNMP::session->error());
      $self->debug("get_table error: try fallback");
      $params{'-maxrepetitions'} = 1;
      $self->debug(sprintf "get_table %s", Data::Dumper::Dumper(\%params));
      $result = $Monitoring::GLPlugin::SNMP::session->get_table(%params);
      $self->debug(sprintf "get_table returned %d oids", scalar(keys %{$result}));
      if (scalar(keys %{$result}) == 0) {
        $self->debug(sprintf "get_table error: %s", 
            $Monitoring::GLPlugin::SNMP::session->error());
        $self->debug("get_table error: no more fallbacks. Try --protocol 1");
      }
    }
    # Drecksstinkstiefel Net::SNMP
    # '1.3.6.1.2.1.2.2.1.22.4 ' => 'endOfMibView',
    # '1.3.6.1.2.1.2.2.1.22.4' => '0.0',
    foreach my $key (keys %{$result}) {
      if (substr($key, -1) eq " ") {
        my $value = $result->{$key};
        delete $result->{$key};
        (my $shortkey = $key) =~ s/\s+$//g;
        if (! exists $result->{shortkey}) {
          $result->{$shortkey} = $value;
        }
        $self->add_rawdata($key, $result->{$key}) if exists $result->{$key};
      } else {
        $self->add_rawdata($key, $result->{$key});
      }
    }
  }
  return $self->get_matching_oids(
      -columns => [$params{'-baseoid'}]);
}

################################################################
# helper functions
# 
sub valid_response {
  my $self = shift;
  my $mib = shift;
  my $oid = shift;
  my $index = shift;
  if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib} &&
      exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$oid}) {
    # make it numerical
    my $oid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$oid};
    if (defined $index) {
      $oid .= '.'.$index;
    }
    my $result = $self->get_request(
        -varbindlist => [$oid]
    );
    if (!defined($result) ||
        ! defined $result->{$oid} ||
        $result->{$oid} eq 'noSuchInstance' ||
        $result->{$oid} eq 'noSuchObject' ||
        $result->{$oid} eq 'endOfMibView') {
      return undef;
    } else {
      $self->add_rawdata($oid, $result->{$oid});
      return $result->{$oid};
    }
  } else {
    return undef;
  }
}

# make_symbolic
# mib is the name of a mib (must be in mibs_and_oids)
# result is a hash-key oid->value
# indices is a array ref of array refs. [[1],[2],...] or [[1,0],[1,1],[2,0]..
sub make_symbolic {
  my $self = shift;
  my $mib = shift;
  my $result = shift;
  my $indices = shift;
  my @entries = ();
  if (! wantarray && ref(\$result) eq "SCALAR" && ref(\$indices) eq "SCALAR") {
    # $self->make_symbolic('CISCO-IETF-NAT-MIB', 'cnatProtocolStatsName', $self->{cnatProtocolStatsName});
    my $oid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$result};
    $result = { $oid => $self->{$result} };
    $indices = [[]];
  }
  foreach my $index (@{$indices}) {
    # skip [], [[]], [[undef]]
    if (ref($index) eq "ARRAY") {
      if (scalar(@{$index}) == 0) {
        next;
      } elsif (!defined $index->[0]) {
        next;
      }
    }
    my $mo = {};
    my $idx = join('.', @{$index}); # index can be multi-level
    foreach my $symoid
        (keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}}) {
      my $oid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid};
      if (ref($oid) ne 'HASH') {
        my $fulloid = $oid . '.'.$idx;
        if (exists $result->{$fulloid}) {
          if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}) {
            if (ref($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}) eq 'HASH') {
              if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}->{$result->{$fulloid}}) {
                $mo->{$symoid} = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}->{$result->{$fulloid}};
              } else {
                $mo->{$symoid} = 'unknown_'.$result->{$fulloid};
              }
            } elsif ($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'} =~ /^OID::(.*)/) {
              my $othermib = $1;
              my $value_which_is_a_oid = $result->{$fulloid};
              $value_which_is_a_oid =~ s/^\.//g;
              my @result = grep { $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$othermib}->{$_} eq $value_which_is_a_oid } keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$othermib}};
              if (scalar(@result)) {
                $mo->{$symoid} = $result[0];
              } else {
                $mo->{$symoid} = 'unknown_'.$result->{$fulloid};
              }
            } elsif ($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'} =~ /^(.*?)::(.*)/) {
              my $mib = $1;
              my $definition = $2;
              if  (exists $Monitoring::GLPlugin::SNMP::definitions->{$mib} &&
                  exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition} &&
                  ref($Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}) eq 'CODE') {
                $mo->{$symoid} = $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->($result->{$fulloid});
              } elsif  (exists $Monitoring::GLPlugin::SNMP::definitions->{$mib} &&
                  exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition} &&
                  ref($Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}) eq 'HASH' &&
                  exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->{$result->{$fulloid}}) {
                $mo->{$symoid} = $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->{$result->{$fulloid}};
              } else {
                $mo->{$symoid} = 'unknown_'.$result->{$fulloid};
              }
            } else {
              $mo->{$symoid} = 'unknown_'.$result->{$fulloid};
              # oder $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}?
            }
          } else {
            $mo->{$symoid} = $result->{$fulloid};
          }
        }
      }
    }
    push(@entries, $mo);
  }
  if (@{$indices} and scalar(@{$indices}) == 1 and !defined $indices->[0]->[0]) {
    my $mo = {};
    foreach my $symoid
        (keys %{$Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}}) {
      my $oid = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid};
      if (ref($oid) ne 'HASH') {
        if (exists $result->{$oid}) {
          if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}) {
            if (ref($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}) eq 'HASH') {
              if (exists $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}->{$result->{$oid}}) {
                $mo->{$symoid} = $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}->{$result->{$oid}};
                push(@entries, $mo);
              }
            } elsif ($Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'} =~ /^(.*?)::(.*)/) {
              my $mib = $1;
              my $definition = $2;
              if  (exists $Monitoring::GLPlugin::SNMP::definitions->{$mib} && exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}
                  && exists $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->{$result->{$oid}}) {
                $mo->{$symoid} = $Monitoring::GLPlugin::SNMP::definitions->{$mib}->{$definition}->{$result->{$oid}};
              } else {
                $mo->{$symoid} = 'unknown_'.$result->{$oid};
              }
            } else {
              $mo->{$symoid} = 'unknown_'.$result->{$oid};
              # oder $Monitoring::GLPlugin::SNMP::mibs_and_oids->{$mib}->{$symoid.'Definition'}?
            }
          }
        }
      }
    }
    push(@entries, $mo) if keys %{$mo};
  }
  if (wantarray) {
    return @entries;
  } else {
    foreach my $entry (@entries) {
      foreach my $key (keys %{$entry}) {
        $self->{$key} = $entry->{$key};
      }
    }
  }
}

sub sort_oids {
  my $self = shift;
  my $oids = shift || [];
  my @sortedkeys = map { $_->[0] }
      sort { $a->[1] cmp $b->[1] }
          map { [$_,
                  join '', map { sprintf("%30d",$_) } split( /\./, $_)
                ] } @{$oids};
  return @sortedkeys;
}

sub get_matching_oids {
  my $self = shift;
  my %params = @_;
  my $result = {};
  $self->debug(sprintf "get_matching_oids %s", Data::Dumper::Dumper(\%params));
  foreach my $oid (@{$params{'-columns'}}) {
    my $oidpattern = $oid;
    $oidpattern =~ s/\./\\./g;
    map { $result->{$_} = $Monitoring::GLPlugin::SNMP::rawdata->{$_} }
        grep /^$oidpattern(?=\.|$)/, keys %{$Monitoring::GLPlugin::SNMP::rawdata};
  }
  $self->debug(sprintf "get_matching_oids returns %d from %d oids", 
      scalar(keys %{$result}), scalar(keys %{$Monitoring::GLPlugin::SNMP::rawdata}));
  return $result;
}

sub get_indices {
  my $self = shift;
  my %params = @_;
  # -baseoid : entry
  # find all oids beginning with $entry
  # then skip one field for the sequence
  # then read the next numindices fields
  my $entrypat = $params{'-baseoid'};
  $entrypat =~ s/\./\\\./g;
  my @indices = map {
      /^$entrypat\.\d+\.(.*)/ && $1;
  } grep {
      /^$entrypat/
  } keys %{$Monitoring::GLPlugin::SNMP::rawdata};
  my %seen = ();
  my @o = map {[split /\./]} sort grep !$seen{$_}++, @indices;
  return @o;
}

# this flattens a n-dimensional array and returns the absolute position
# of the element at position idx1,idx2,...,idxn
# element 1,2 in table 0,0 0,1 0,2 1,0 1,1 1,2 2,0 2,1 2,2 is at pos 6
sub get_number {
  my $self = shift;
  my $indexlists = shift; #, zeiger auf array aus [1, 2]
  my @element = @_;
  my $dimensions = scalar(@{$indexlists->[0]});
  my @sorted = ();
  my $number = 0;
  if ($dimensions == 1) {
    @sorted =
        sort { $a->[0] <=> $b->[0] } @{$indexlists};
  } elsif ($dimensions == 2) {
    @sorted =
        sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] } @{$indexlists};
  } elsif ($dimensions == 3) {
    @sorted =
        sort { $a->[0] <=> $b->[0] ||
               $a->[1] <=> $b->[1] ||
               $a->[2] <=> $b->[2] } @{$indexlists};
  }
  foreach (@sorted) {
    if ($dimensions == 1) {
      if ($_->[0] == $element[0]) {
        last;
      }
    } elsif ($dimensions == 2) {
      if ($_->[0] == $element[0] && $_->[1] == $element[1]) {
        last;
      }
    } elsif ($dimensions == 3) {
      if ($_->[0] == $element[0] &&
          $_->[1] == $element[1] &&
          $_->[2] == $element[2]) {
        last;
      }
    }
    $number++;
  }
  return ++$number;
}

################################################################
# caching functions
# 
sub set_rawdata {
  my $self = shift;
  $Monitoring::GLPlugin::SNMP::rawdata = shift;
}

sub add_rawdata {
  my $self = shift;
  my $oid = shift;
  my $value = shift;
  $Monitoring::GLPlugin::SNMP::rawdata->{$oid} = $value;
}

sub rawdata {
  my $self = shift;
  return $Monitoring::GLPlugin::SNMP::rawdata;
}

sub add_oidtrace {
  my $self = shift;
  my $oid = shift;
  $self->debug("cache: ".$oid);
  push(@{$Monitoring::GLPlugin::SNMP::oidtrace}, $oid);
}

#  $self->update_entry_cache(0, $mib, $table, $key_attr);
#  my @indices = $self->get_cache_indices();
sub get_cache_indices {
  my $self = shift;
  my $mib = shift;
  my $table = shift;
  my $key_attr = shift;
  if (ref($key_attr) ne "ARRAY") {
    $key_attr = [$key_attr];
  }
  my $cache = sprintf "%s_%s_%s_cache", 
      $mib, $table, join('#', @{$key_attr});
  my @indices = ();
  foreach my $key (keys %{$self->{$cache}}) {
    my ($descr, $index) = split('-//-', $key, 2);
    if ($self->opts->name) {
      if ($self->opts->regexp) {
        my $pattern = $self->opts->name;
        if ($descr =~ /$pattern/i) {
          push(@indices, $self->{$cache}->{$key});
        }
      } else {
        if ($self->opts->name =~ /^\d+$/) {
          if ($index == 1 * $self->opts->name) {
            push(@indices, [1 * $self->opts->name]);
          }
        } else {
          if (lc $descr eq lc $self->opts->name) {
            push(@indices, $self->{$cache}->{$key});
          }
        }
      }
    } else {
      push(@indices, $self->{$cache}->{$key});
    }
  }
  return @indices;
  return map { join('.', ref($_) eq "ARRAY" ? @{$_} : $_) } @indices;
}


package Monitoring::GLPlugin::SNMP::CSF;
#our @ISA = qw(Monitoring::GLPlugin::SNMP);
use Digest::MD5 qw(md5_hex);
use strict;

sub create_statefile {
  my $self = shift;
  my %params = @_;
  my $extension = "";
  $extension .= $params{name} ? '_'.$params{name} : '';
  if ($self->opts->community) {
    $extension .= md5_hex($self->opts->community);
  }
  $extension =~ s/\//_/g;
  $extension =~ s/\(/_/g;
  $extension =~ s/\)/_/g;
  $extension =~ s/\*/_/g;
  $extension =~ s/\s/_/g;
  if ($self->opts->snmpwalk && ! $self->opts->hostname) {
    return sprintf "%s/%s_%s%s", $self->statefilesdir(),
        'snmpwalk.file'.md5_hex($self->opts->snmpwalk),
        $self->opts->mode, lc $extension;
  } elsif ($self->opts->snmpwalk && $self->opts->hostname eq "walkhost") {
    return sprintf "%s/%s_%s%s", $self->statefilesdir(),
        'snmpwalk.file'.md5_hex($self->opts->snmpwalk),
        $self->opts->mode, lc $extension;
  } else {
    return sprintf "%s/%s_%s%s", $self->statefilesdir(),
        $self->opts->hostname, $self->opts->mode, lc $extension;
  }
}

package Monitoring::GLPlugin::SNMP::Item;
our @ISA = qw(Monitoring::GLPlugin::SNMP::CSF Monitoring::GLPlugin::Item Monitoring::GLPlugin::SNMP);
use strict;


package Monitoring::GLPlugin::SNMP::TableItem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::CSF Monitoring::GLPlugin::TableItem Monitoring::GLPlugin::SNMP);
use strict;

sub ensure_index {
  my $self = shift;
  my $key = shift;
  $self->{$key} ||= $self->{flat_indices};
}

sub unhex_ip {
  my $self = shift;
  my $value = shift;
  if ($value && $value =~ /^0x(\w{8})/) {
    $value = join(".", unpack "C*", pack "H*", $1);
  } elsif ($value && $value =~ /^0x(\w{2} \w{2} \w{2} \w{2})/) {
    $value = $1;
    $value =~ s/ //g;
    $value = join(".", unpack "C*", pack "H*", $value);
  } elsif ($value && $value =~ /^([A-Z0-9]{2} [A-Z0-9]{2} [A-Z0-9]{2} [A-Z0-9]{2})/i) {
    $value = $1;
    $value =~ s/ //g;
    $value = join(".", unpack "C*", pack "H*", $value);
  } elsif ($value && unpack("H8", $value) =~ /(\w{2})(\w{2})(\w{2})(\w{2})/) {
    $value = join(".", map { hex($_) } ($1, $2, $3, $4));
  }
  return $value;
}

sub unhex_mac {
  my $self = shift;
  my $value = shift;
  if ($value && $value =~ /^0x(\w{12})/) {
    $value = join(".", unpack "C*", pack "H*", $1);
  } elsif ($value && $value =~ /^0x(\w{2}\s*\w{2}\s*\w{2}\s*\w{2}\s*\w{2}\s*\w{2})/) {
    $value = $1;
    $value =~ s/ //g;
    $value = join(":", unpack "C*", pack "H*", $value);
  } elsif ($value && unpack("H12", $value) =~ /(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})/) {
    $value = join(":", map { hex($_) } ($1, $2, $3, $4, $5, $6));
  }
  return $value;
}


package Monitoring::GLPlugin::UPNP;
our @ISA = qw(Monitoring::GLPlugin);

use strict;
use File::Basename;
use Digest::MD5 qw(md5_hex);
use AutoLoader;
our $AUTOLOAD;

use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

{
  our $mode = undef;
  our $plugin = undef;
  our $blacklist = undef;
  our $session = undef;
  our $rawdata = {};
  our $info = [];
  our $extendedinfo = [];
  our $summary = [];
  our $oidtrace = [];
  our $uptime = 0;
}

sub init {
  my $self = shift;
  if ($self->mode =~ /device::walk/) {
  } elsif ($self->mode =~ /device::uptime/) {
    my $info = sprintf 'device is up since %s',
        $self->human_timeticks($self->{uptime});
    $self->add_info($info);
    $self->set_thresholds(warning => '15:', critical => '5:');
    $self->add_message($self->check_thresholds($self->{uptime}), $info);
    $self->add_perfdata(
        label => 'uptime',
        value => $self->{uptime} / 60,
        warning => $self->{warning},
        critical => $self->{critical},
    );
    my ($code, $message) = $self->check_messages(join => ', ', join_all => ', ');
    $Monitoring::GLPlugin::plugin->nagios_exit($code, $message);
  }
}

sub check_upnp_and_model {
  my $self = shift;
  if (eval "require SOAP::Lite") {
    require XML::LibXML;
  } else {
    $self->add_critical('could not find SOAP::Lite module');
  }
  $self->{services} = {};
  if (! $self->check_messages()) {
    eval {
      my $igddesc = sprintf "http://%s:%s/igddesc.xml",
          $self->opts->hostname, $self->opts->port;
      my $parser = XML::LibXML->new();
      my $doc = $parser->parse_file($igddesc);
      my $root = $doc->documentElement();
      my $xpc = XML::LibXML::XPathContext->new( $root );
      $xpc->registerNs('n', 'urn:schemas-upnp-org:device-1-0');
      $self->{productname} = $xpc->findvalue('(//n:device)[position()=1]/n:modelName' );
      my @services = ();
      my @servicedescs = $xpc->find('(//n:service)')->get_nodelist;
      foreach my $service (@servicedescs) {
        my $servicetype = undef;
        my $serviceid = undef;
        my $controlurl = undef;
        foreach my $node ($service->nonBlankChildNodes("./*")) {
          $serviceid = $node->textContent if ($node->nodeName eq "serviceId");
          $servicetype = $node->textContent if ($node->nodeName eq "serviceType");
          $controlurl = $node->textContent if ($node->nodeName eq "controlURL");
        }
        if ($serviceid && $controlurl) {
          push(@services, {
              serviceType => $servicetype,
              serviceId => $serviceid,
              controlURL => sprintf('http://%s:%s%s',
                  $self->opts->hostname, $self->opts->port, $controlurl),
          });
        }
      }
      $self->set_variable('services', \@services);
    };
    if ($@) {
      $self->add_critical($@);
    }
  }
  if (! $self->check_messages()) {
    eval {
      my $service = (grep { $_->{serviceId} =~ /WANIPConn1/ } @{$self->get_variable('services')})[0];
      my $som = SOAP::Lite
          -> proxy($service->{controlURL})
          -> uri($service->{serviceType})
          -> GetStatusInfo();
      $self->{uptime} = $som->valueof("//GetStatusInfoResponse/NewUptime");
      $self->{uptime} /= 1.0;
    };
    if ($@) {
      $self->add_critical("could not get uptime: ".$@);
    }
  }
}

sub create_statefile {
  my $self = shift;
  my %params = @_;
  my $extension = "";
  $extension .= $params{name} ? '_'.$params{name} : '';
  if ($self->opts->community) {
    $extension .= md5_hex($self->opts->community);
  }
  $extension =~ s/\//_/g;
  $extension =~ s/\(/_/g;
  $extension =~ s/\)/_/g;
  $extension =~ s/\*/_/g;
  $extension =~ s/\s/_/g;
  return sprintf "%s/%s_%s%s", $self->statefilesdir(),
      $self->opts->hostname, $self->opts->mode, lc $extension;
}


package Classes::UPNP::AVM::FritzBox7390::Component::InterfaceSubsystem;
our @ISA = qw(Classes::IFMIB::Component::InterfaceSubsystem);
use strict;


sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces/) {
    $self->{ifDescr} = "WAN";
    my $service = (grep { $_->{serviceId} =~ /WANIPConn1/ } @{$self->get_variable('services')})[0];
    $self->{ExternalIPAddress} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetExternalIPAddress()
      -> result;
    $self->{ConnectionStatus} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetStatusInfo()
      -> valueof("//GetStatusInfoResponse/NewConnectionStatus");;
    $service = (grep { $_->{serviceId} =~ /WANCommonIFC1/ } @{$self->get_variable('services')})[0];
    $self->{PhysicalLinkStatus} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetCommonLinkProperties()
      -> valueof("//GetCommonLinkPropertiesResponse/NewPhysicalLinkStatus");
    $self->{Layer1UpstreamMaxBitRate} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetCommonLinkProperties()
      -> valueof("//GetCommonLinkPropertiesResponse/NewLayer1UpstreamMaxBitRate");
    $self->{Layer1DownstreamMaxBitRate} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetCommonLinkProperties()
      -> valueof("//GetCommonLinkPropertiesResponse/NewLayer1DownstreamMaxBitRate");
    $self->{TotalBytesSent} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetTotalBytesSent()
      -> result;
    $self->{TotalBytesReceived} = SOAP::Lite
      -> proxy($service->{controlURL})
      -> uri($service->{serviceType})
      -> GetTotalBytesReceived()
      -> result;
    if ($self->mode =~ /device::interfaces::usage/) {
      $self->valdiff({name => $self->{ifDescr}}, qw(TotalBytesSent TotalBytesReceived));
      $self->{inputUtilization} = $self->{delta_TotalBytesReceived} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{Layer1DownstreamMaxBitRate});
      $self->{outputUtilization} = $self->{delta_TotalBytesSent} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{Layer1UpstreamMaxBitRate});
      $self->{inputRate} = $self->{delta_TotalBytesReceived} / $self->{delta_timestamp};
      $self->{outputRate} = $self->{delta_TotalBytesSent} / $self->{delta_timestamp};
      my $factor = 1/8; # default Bits
      if ($self->opts->units) {
        if ($self->opts->units eq "GB") {
          $factor = 1024 * 1024 * 1024;
        } elsif ($self->opts->units eq "MB") {
          $factor = 1024 * 1024;
        } elsif ($self->opts->units eq "KB") {
          $factor = 1024;
        } elsif ($self->opts->units eq "GBi") {
          $factor = 1024 * 1024 * 1024 / 8;
        } elsif ($self->opts->units eq "MBi") {
          $factor = 1024 * 1024 / 8;
        } elsif ($self->opts->units eq "KBi") {
          $factor = 1024 / 8;
        } elsif ($self->opts->units eq "B") {
          $factor = 1;
        } elsif ($self->opts->units eq "Bit") {
          $factor = 1/8;
        }
      }
      $self->{inputRate} /= $factor;
      $self->{outputRate} /= $factor;
      $self->{Layer1DownstreamMaxKBRate} =
          ($self->{Layer1DownstreamMaxBitRate} / 8) / 1024;
      $self->{Layer1UpstreamMaxKBRate} =
          ($self->{Layer1UpstreamMaxBitRate} / 8) / 1024;
    } elsif ($self->mode =~ /device::interfaces::operstatus/) {
    } elsif ($self->mode =~ /device::interfaces::list/) {
    } else {
      $self->no_such_mode();
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking interfaces');
  if ($self->mode =~ /device::interfaces::usage/) {
    $self->add_info(sprintf 'interface %s usage is in:%.2f%% (%s) out:%.2f%% (%s)',
        $self->{ifDescr},
        $self->{inputUtilization},
        sprintf("%.2f%s/s", $self->{inputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')),
        $self->{outputUtilization},
        sprintf("%.2f%s/s", $self->{outputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')));
    $self->set_thresholds(warning => 80, critical => 90);
    my $in = $self->check_thresholds($self->{inputUtilization});
    my $out = $self->check_thresholds($self->{outputUtilization});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization},
        uom => '%',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization},
        uom => '%',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_in',
        value => $self->{inputRate},
        uom => $self->opts->units,
        thresholds => 0,
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_out',
        value => $self->{outputRate},
        uom => $self->opts->units,
        thresholds => 0,
    );
  } elsif ($self->mode =~ /device::interfaces::operstatus/) {
    $self->add_info(sprintf 'interface %s%s status is %s',
        $self->{ifDescr}, 
        $self->{ExternalIPAddress} ? " (".$self->{ExternalIPAddress}.")" : "",
        $self->{ConnectionStatus});
    if ($self->{ConnectionStatus} eq "Connected") {
      $self->add_ok();
    } else {
      $self->add_critical();
    }
  } elsif ($self->mode =~ /device::interfaces::list/) {
    printf "%s\n", $self->{ifDescr};
    $self->add_ok("have fun");
  }
}

package Classes::UPNP::AVM::FritzBox7390::Component::SmartHomeSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item Classes::UPNP::AVM::FritzBox7390);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /smarthome::device::list/) {
    $self->update_device_cache(1);
    foreach my $ain (keys %{$self->{device_cache}}) {
      my $name = $self->{device_cache}->{$ain}->{name};
      printf "%02d %s\n", $ain, $name;
    }
  } elsif ($self->mode =~ /smarthome::device/) {
    $self->update_device_cache(0);
    my @indices = $self->get_device_indices();
    foreach my $ain (map {$_->[0]} @indices) {
      my %tmp_dev = (ain => $ain, name => $self->{device_cache}->{$ain}->{name});
      push(@{$self->{smart_home_devices}},
          Classes::UPNP::AVM::FritzBox7390::Component::SmartHomeSubsystem::Device->new(%tmp_dev));
    }
  }
}

sub check {
  my $self = shift;
  foreach (@{$self->{smart_home_devices}}) {
    $_->check();
  }
}

sub create_device_cache_file {
  my $self = shift;
  my $extension = "";
  if ($self->opts->community) {
    $extension .= Digest::MD5::md5_hex($self->opts->community);
  }
  $extension =~ s/\//_/g;
  $extension =~ s/\(/_/g;
  $extension =~ s/\)/_/g;
  $extension =~ s/\*/_/g;
  $extension =~ s/\s/_/g;
  return sprintf "%s/%s_interface_cache_%s", $self->statefilesdir(),
      $self->opts->hostname, lc $extension;
}

sub update_device_cache {
  my $self = shift;
  my $force = shift;
  my $statefile = $self->create_device_cache_file();
  my $update = time - 3600;
  if ($force || ! -f $statefile || ((stat $statefile)[9]) < ($update)) {
    $self->debug('force update of device cache');
    $self->{device_cache} = {};
    my $switchlist = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchlist');
    my @ains = split(",", $switchlist);
    foreach my $ain (@ains) {
      chomp $ain;
      my $name = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchname&ain='.$ain);
      chomp $name;
      $self->{device_cache}->{$ain}->{name} = $name;
    }
    $self->save_device_cache();
  }
  $self->load_device_cache();
}

sub save_device_cache {
  my $self = shift;
  $self->create_statefilesdir();
  my $statefile = $self->create_device_cache_file();
  my $tmpfile = $self->statefilesdir().'/check_nwc_health_tmp_'.$$;
  my $fh = IO::File->new();
  $fh->open(">$tmpfile");
  $fh->print(Data::Dumper::Dumper($self->{device_cache}));
  $fh->flush();
  $fh->close();
  my $ren = rename $tmpfile, $statefile;
  $self->debug(sprintf "saved %s to %s",
      Data::Dumper::Dumper($self->{device_cache}), $statefile);
}

sub load_device_cache {
  my $self = shift;
  my $statefile = $self->create_device_cache_file();
  if ( -f $statefile) {
    our $VAR1;
    eval {
      require $statefile;
    };
    if($@) {
      printf "rumms\n";
    }
    $self->debug(sprintf "load %s", Data::Dumper::Dumper($VAR1));
    $self->{device_cache} = $VAR1;
    eval {
      foreach (keys %{$self->{device_cache}}) {
        /^\d+$/ || die "newrelease";
      }
    };
    if($@) {
      $self->{device_cache} = {};
      unlink $statefile;
      delete $INC{$statefile};
      $self->update_device_cache(1);
    }
  }
}

sub get_device_indices {
  my $self = shift;
  my @indices = ();
  foreach my $id (keys %{$self->{device_cache}}) {
    my $name = $self->{device_cache}->{$id}->{name};
    if ($self->opts->name) {
      if ($self->opts->regexp) {
        my $pattern = $self->opts->name;
        if ($name =~ /$pattern/i) {
          push(@indices, [$id]);
        }
      } else {
        if ($self->opts->name =~ /^\d+$/) {
          if ($id == 1 * $self->opts->name) {
            push(@indices, [1 * $self->opts->name]);
          }
        } else {
          if (lc $name eq lc $self->opts->name) {
            push(@indices, [$id]);
          }
        }
      }
    } else {
      push(@indices, [$id]);
    }
  }
  return @indices;
}


package Classes::UPNP::AVM::FritzBox7390::Component::SmartHomeSubsystem::Device;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem Classes::UPNP::AVM::FritzBox7390::Component::SmartHomeSubsystem);
use strict;

sub finish {
  my $self = shift;
  if ($self->mode =~ /smarthome::device::status/) {
    $self->{connected} = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchpresent&ain='.$self->{ain});
    $self->{switched} = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchstate&ain='.$self->{ain});
    chomp $self->{connected};
    chomp $self->{switched};
  } elsif ($self->mode =~ /smarthome::device::energy/) {
    eval {
      $self->{last_watt} = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchpower&ain='.$self->{ain});
      $self->{last_watt} /= 1000;
    };
  } elsif ($self->mode =~ /smarthome::device::consumption/) {
    eval {
      $self->{kwh} = $self->http_get('/webservices/homeautoswitch.lua?switchcmd=getswitchenergy&ain='.$self->{ain});
      $self->{kwh} /= 1000;
    };
  }
}

sub check {
  my $self = shift;
  if ($self->mode =~ /smarthome::device::status/) {
    $self->add_info(sprintf "device %s is %sconnected and switched %s",
        $self->{name}, $self->{connected} ? "" : "not ", $self->{switched} ? "on" : "off");
    if (! $self->{connected} || ! $self->{switched}) {
      $self->add_critical();
    } else {
      $self->add_ok(sprintf "device %s ok", $self->{name});
    }
  } elsif ($self->mode =~ /smarthome::device::energy/) {
    $self->add_info(sprintf "device %s consumes %.4f watts",
        $self->{name}, $self->{last_watt});
    $self->set_thresholds(
        warning => 80 / 100 * 220 * 10, 
        critical => 90 / 100 * 220 * 10);
    $self->add_message($self->check_thresholds($self->{last_watt}));
    $self->add_perfdata(
        label => 'watt',
        value => $self->{last_watt},
    );
  } elsif ($self->mode =~ /smarthome::device::consumption/) {
    $self->add_info(sprintf "device %s consumed %.4f kwh",
        $self->{name}, $self->{kwh});
    $self->set_thresholds(warning => 1000, critical => 1000);
    $self->add_message($self->check_thresholds($self->{kwh}));
    $self->add_perfdata(
        label => 'kwh',
        value => $self->{kwh},
    );
  }
}
package Classes::UPNP::AVM::FritzBox7390;
our @ISA = qw(Classes::UPNP::AVM);
use strict;

{
  our $sid = undef;
}

sub sid : lvalue {
  my $self = shift;
  $Classes::UPNP::AVM::FritzBox7390::sid;
}

sub init {
  my $self = shift;
  foreach my $module (qw(HTML::TreeBuilder LWP::UserAgent Encode Digest::MD5 JSON)) {
    if (! eval "require $module") {
      $self->add_unknown("could not find $module module");
    }
  }
  $self->login();
  if (! $self->check_messages()) {
    if ($self->mode =~ /device::hardware::health/) {
      $self->analyze_environmental_subsystem();
      $self->check_environmental_subsystem();
    } elsif ($self->mode =~ /device::hardware::load/) {
      $self->analyze_cpu_subsystem();
      $self->check_cpu_subsystem();
    } elsif ($self->mode =~ /device::hardware::memory/) {
      $self->analyze_mem_subsystem();
      $self->check_mem_subsystem();
    } elsif ($self->mode =~ /device::interfaces/) {
      $self->analyze_and_check_interface_subsystem("Classes::UPNP::AVM::FritzBox7390::Component::InterfaceSubsystem");
    } elsif ($self->mode =~ /device::smarthome/) {
      $self->analyze_and_check_smarthome_subsystem("Classes::UPNP::AVM::FritzBox7390::Component::SmartHomeSubsystem");
    } else {
      $self->logout();
      $self->no_such_mode();
    }
  }
  $self->logout();
}

sub login {
  my $self = shift;
  my $ua = LWP::UserAgent->new;
  my $loginurl = sprintf "http://%s/login_sid.lua", $self->opts->hostname;
  my $resp = $ua->get($loginurl);
  my $content = $resp->content();
  my $challenge = ($content =~ /<Challenge>(.*?)<\/Challenge>/ && $1);
  my $input = $challenge . '-' . $self->opts->community;
  Encode::from_to($input, 'ascii', 'utf16le');
  my $challengeresponse = $challenge . '-' . lc(Digest::MD5::md5_hex($input));
  $resp = HTTP::Request->new(POST => $loginurl);
  $resp->content_type("application/x-www-form-urlencoded");
  my $login = "response=$challengeresponse";
  if ($self->opts->username) {
      $login .= "&username=" . $self->opts->username;
  }
  $resp->content($login);
  my $loginresp = $ua->request($resp);
  $content = $loginresp->content();
  $self->sid() = ($content =~ /<SID>(.*?)<\/SID>/ && $1);
  if (! $loginresp->is_success() || ! $self->sid() || $self->sid() =~ /^0+$/) {
    $self->add_critical($loginresp->status_line());
  } else {
    $self->debug("logged in with sid ".$self->sid());
  }
}

sub logout {
  my $self = shift;
  return if ! $self->sid();
  my $ua = LWP::UserAgent->new;
  my $loginurl = sprintf "http://%s/login_sid.lua", $self->opts->hostname;
  my $resp = HTTP::Request->new(POST => $loginurl);
  $resp->content_type("application/x-www-form-urlencoded");
  my $logout = "sid=".$self->sid()."&security:command/logout=1";
  $resp->content($logout);
  my $logoutresp = $ua->request($resp);
  $self->sid() = undef;
  $self->debug("logged out");
}

sub DESTROY {
  my $self = shift;
  $self->logout();
}

sub http_get {
  my $self = shift;
  my $page = shift;
  my $ua = LWP::UserAgent->new;
  if ($page =~ /\?/) {
    $page .= "&sid=".$self->sid();
  } else {
    $page .= "?sid=".$self->sid();
  }
  my $url = sprintf "http://%s/%s", $self->opts->hostname, $page;
  $self->debug("http get ".$url);
  my $resp = $ua->get($url);
  if (! $resp->is_success()) {
    $self->add_critical($resp->status_line());
  } else {
  }
  return $resp->content();
}

sub analyze_cpu_subsystem {
  my $self = shift;
  my $html = $self->http_get('system/ecostat.lua');
  if ($html =~ /uiSubmitLogin/) {
    $self->add_critical("wrong login");
    $self->{cpu_usage} = 0;
  } else {
    my $cpu = (grep /StatCPU/, split(/\n/, $html))[0];
    my @cpu = ($cpu =~ /= "(.*?)"/ && split(/,/, $1));
    $self->{cpu_usage} = $cpu[0];
  }
}

sub analyze_mem_subsystem {
  my $self = shift;
  my $html = $self->http_get('system/ecostat.lua');
  if ($html =~ /uiSubmitLogin/) {
    $self->add_critical("wrong login");
    $self->{ram_used} = 0;
  } else {
    my $ramcacheused = (grep /StatRAMCacheUsed/, split(/\n/, $html))[0];
    my @ramcacheused = ($ramcacheused =~ /= "(.*?)"/ && split(/,/, $1));
    $self->{ram_cache_used} = $ramcacheused[0];
    my $ramphysfree = (grep /StatRAMPhysFree/, split(/\n/, $html))[0];
    my @ramphysfree = ($ramphysfree =~ /= "(.*?)"/ && split(/,/, $1));
    $self->{ram_phys_free} = $ramphysfree[0];
    my $ramstrictlyused = (grep /StatRAMStrictlyUsed/, split(/\n/, $html))[0];
    my @ramstrictlyused = ($ramstrictlyused =~ /= "(.*?)"/ && split(/,/, $1));
    $self->{ram_strictly_used} = $ramstrictlyused[0];
    $self->{ram_used} = $self->{ram_strictly_used} + $self->{ram_cache_used};
  }
}

sub check_cpu_subsystem {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{cpu_usage});
  $self->set_thresholds(warning => 40, critical => 60);
  $self->add_message($self->check_thresholds($self->{cpu_usage}), $self->{info});
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{cpu_usage},
      uom => '%',
      warning => $self->{warning},
      critical => $self->{critical},
  );
}

sub check_mem_subsystem {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'memory usage is %.2f%%', $self->{ram_used});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{ram_used}), $self->{info});
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{ram_used},
      uom => '%',
      warning => $self->{warning},
      critical => $self->{critical},
  );
}





package Classes::UPNP::AVM;
our @ISA = qw(Classes::UPNP);
use strict;

sub init {
  my $self = shift;
  if ($self->{productname} =~ /7390/) {
    bless $self, 'Classes::UPNP::AVM::FritzBox7390';
    $self->debug('using Classes::UPNP::AVM::FritzBox7390');
  } else {
    $self->no_such_model();
  }
  if (ref($self) ne "Classes::UPNP::AVM") {
    $self->init();
  }
}

package Classes::UPNP;
our @ISA = qw(Classes::Device);
use strict;

package Server::Linux;
our @ISA = qw(Classes::Device);
use strict;


sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces/) {
    $self->analyze_and_check_interface_subsystem('Server::Linux::Component::InterfaceSubsystem');
  }
}


package Server::Linux::Component::InterfaceSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{interfaces} = [];
  if ($self->mode =~ /device::interfaces::list/) {
    foreach (glob "/sys/class/net/*") {
      my $name = $_;
      next if ! -d $name;
      $name =~ s/.*\///g;
      my $tmpif = {
        ifDescr => $name,
      };
      push(@{$self->{interfaces}},
        Server::Linux::Component::InterfaceSubsystem::Interface->new(%{$tmpif}));
    }
  } else {
    foreach (glob "/sys/class/net/*") {
      my $name = $_;
      $name =~ s/.*\///g;
      if ($self->opts->name) {
        if ($self->opts->regexp) {
          my $pattern = $self->opts->name;
          if ($name !~ /$pattern/i) {
            next;
          }
        } elsif (lc $name ne lc $self->opts->name) {
          next;
        }
      }
      *SAVEERR = *STDERR;
      open ERR ,'>/dev/null';
      *STDERR = *ERR;
      my $tmpif = {
        ifDescr => $name,
        ifSpeed => (-f "/sys/class/net/$name/speed" ? do { local (@ARGV, $/) = "/sys/class/net/$name/speed"; my $x = <>; close ARGV; $x} * 1024*1024 : undef),
        ifInOctets => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/rx_bytes"; my $x = <>; close ARGV; $x},
        ifInDiscards => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/rx_dropped"; my $x = <>; close ARGV; $x},
        ifInErrors => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/rx_errors"; my $x = <>; close ARGV; $x},
        ifOutOctets => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/tx_bytes"; my $x = <>; close ARGV; $x},
        ifOutDiscards => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/tx_dropped"; my $x = <>; close ARGV; $x},
        ifOutErrors => do { local (@ARGV, $/) = "/sys/class/net/$name/statistics/tx_errors"; my $x = <>; close ARGV; $x},
      };
      *STDERR = *SAVEERR;
      foreach (keys %{$tmpif}) {
        chomp($tmpif->{$_}) if defined $tmpif->{$_};
      }
      if (defined $self->opts->ifspeed) {
        $tmpif->{ifSpeed} = $self->opts->ifspeed * 1024*1024;
      }
      if (! defined $tmpif->{ifSpeed}) {
        $self->add_unknown(sprintf "There is no /sys/class/net/%s/speed. Use --ifspeed", $name);
      } else {
        push(@{$self->{interfaces}},
          Server::Linux::Component::InterfaceSubsystem::Interface->new(%{$tmpif}));
      }
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking interfaces');
  if (scalar(@{$self->{interfaces}}) == 0) {
    $self->add_unknown('no interfaces');
    return;
  }
  if ($self->mode =~ /device::interfaces::list/) {
    foreach (sort {$a->{ifDescr} cmp $b->{ifDescr}} @{$self->{interfaces}}) {
      $_->list();
    }
  } else {
    foreach (@{$self->{interfaces}}) {
      $_->check();
    }
  }
}


package Server::Linux::Component::InterfaceSubsystem::Interface;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  foreach (qw(ifSpeed ifInOctets ifInDiscards ifInErrors ifOutOctets ifOutDiscards ifOutErrors)) {
    $self->{$_} = 0 if ! defined $self->{$_};
  }
  if ($self->mode =~ /device::interfaces::traffic/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInOctets ifInDiscards ifInErrors ifOutOctets ifOutDiscards ifOutErrors));
  } elsif ($self->mode =~ /device::interfaces::usage/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInOctets ifOutOctets));
    if ($self->{ifSpeed} == 0) {
      # vlan graffl
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    } else {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{maxInputRate} = $self->{ifSpeed};
      $self->{maxOutputRate} = $self->{ifSpeed};
    }
    if (defined $self->opts->ifspeedin) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedin);
      $self->{maxInputRate} = $self->opts->ifspeedin;
    }
    if (defined $self->opts->ifspeedout) {
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedout);
      $self->{maxOutputRate} = $self->opts->ifspeedout;
    }
    if (defined $self->opts->ifspeed) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{maxInputRate} = $self->opts->ifspeed;
      $self->{maxOutputRate} = $self->opts->ifspeed;
    }
    $self->{inputRate} = $self->{delta_ifInOctets} / $self->{delta_timestamp};
    $self->{outputRate} = $self->{delta_ifOutOctets} / $self->{delta_timestamp};
    $self->{maxInputRate} /= 8; # auf octets umrechnen wie die in/out
    $self->{maxOutputRate} /= 8;
    my $factor = 1/8; # default Bits
    if ($self->opts->units) {
      if ($self->opts->units eq "GB") {
        $factor = 1024 * 1024 * 1024;
      } elsif ($self->opts->units eq "MB") {
        $factor = 1024 * 1024;
      } elsif ($self->opts->units eq "KB") {
        $factor = 1024;
      } elsif ($self->opts->units eq "GBi") {
        $factor = 1024 * 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "MBi") {
        $factor = 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "KBi") {
        $factor = 1024 / 8;
      } elsif ($self->opts->units eq "B") {
        $factor = 1;
      } elsif ($self->opts->units eq "Bit") {
        $factor = 1/8;
      }
    }
    $self->{inputRate} /= $factor;
    $self->{outputRate} /= $factor;
    $self->{maxInputRate} /= $factor;
    $self->{maxOutputRate} /= $factor;
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInErrors ifOutErrors));
    $self->{inputErrorRate} = $self->{delta_ifInErrors}
        / $self->{delta_timestamp};
    $self->{outputErrorRate} = $self->{delta_ifOutErrors}
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInDiscards ifOutDiscards));
    $self->{inputDiscardRate} = $self->{delta_ifInDiscards}
        / $self->{delta_timestamp};
    $self->{outputDiscardRate} = $self->{delta_ifOutDiscards}
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::operstatus/) {
  }
  return $self;
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::traffic/) {
  } elsif ($self->mode =~ /device::interfaces::usage/) {
    $self->add_info(sprintf 'interface %s usage is in:%.2f%% (%s) out:%.2f%% (%s)',
        $self->{ifDescr},
        $self->{inputUtilization},
        sprintf("%.2f%s/s", $self->{inputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')),
        $self->{outputUtilization},
        sprintf("%.2f%s/s", $self->{outputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')));
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        warning => 80,
        critical => 90
    );
    my $in = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization}
    );
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        warning => 80,
        critical => 90
    );
    my $out = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization}
    );
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization},
        uom => '%',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization},
        uom => '%',
    );

    my ($inwarning, $incritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_in',
        value => $self->{inputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxInputRate},
        warning => $self->{maxInputRate} / 100 * $inwarning,
        critical => $self->{maxInputRate} / 100 * $incritical,
    );
    my ($outwarning, $outcritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_out',
        value => $self->{outputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxOutputRate},
        warning => $self->{maxOutputRate} / 100 * $outwarning,
        critical => $self->{maxOutputRate} / 100 * $outcritical,
    );
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->add_info(sprintf 'interface %s errors in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputErrorRate} , $self->{outputErrorRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputErrorRate});
    my $out = $self->check_thresholds($self->{outputErrorRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_in',
        value => $self->{inputErrorRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_out',
        value => $self->{outputErrorRate},
    );
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->add_info(sprintf 'interface %s discards in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputDiscardRate} , $self->{outputDiscardRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputDiscardRate});
    my $out = $self->check_thresholds($self->{outputDiscardRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_in',
        value => $self->{inputDiscardRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_out',
        value => $self->{outputDiscardRate},
    );
  }
}

sub list {
  my $self = shift;
  printf "%s\n", $self->{ifDescr};
}

package Server::Windows;
our @ISA = qw(Classes::Device);
use strict;


sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces/) {
    $self->analyze_and_check_interface_subsystem('Server::Windows::Component::InterfaceSubsystem');
  }
}


package Server::Windows::Component::InterfaceSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{interfaces} = [];
# bits per second
  if ($self->mode =~ /device::interfaces::list/) {
    my $dbh = DBI->connect('dbi:WMI:');
    my $sth = $dbh->prepare("select * from Win32_PerfRawData_Tcpip_NetworkInterface");
    $sth->execute();
    while (my $member_arr = $sth->fetchrow_arrayref()) {
      my $member = $member_arr->[0];
      my $tmpif = {
        ifDescr => $member->{Name},
      };
      push(@{$self->{interfaces}},
        Server::Windows::Component::InterfaceSubsystem::Interface->new(%{$tmpif}));
    }
  } else {
    my $dbh = DBI->connect('dbi:WMI:');
    my $sth = $dbh->prepare("select * from Win32_PerfRawData_Tcpip_NetworkInterface");
    $sth->execute();
    while (my $member_arr = $sth->fetchrow_arrayref()) {
      my $i = 0;
      my $member = $member_arr->[0];
      my $name = $member->{Name};
      $name =~ s/.*\///g;
      if ($self->opts->name) {
        if ($self->opts->regexp) {
          my $pattern = $self->opts->name;
          if ($name !~ /$pattern/i) {
            next;
          }
        } elsif (lc $name ne lc $self->opts->name) {
          next;
        }
      }
      *SAVEERR = *STDERR;
      open ERR ,'>/dev/null';
      *STDERR = *ERR;
      my $tmpif = {
        ifDescr => $name,
        ifSpeed => $member->{CurrentBandwidth},
        ifInOctets => $member->{BytesReceivedPerSec},
        ifInDiscards => $member->{PacketsReceivedDiscarded},
        ifInErrors => $member->{PacketsReceivedErrors},
        ifOutOctets => $member->{BytesSentPerSec},
        ifOutDiscards => $member->{PacketsOutboundDiscarded},
        ifOutErrors => $member->{PacketsOutboundErrors},
      };
      *STDERR = *SAVEERR;
      foreach (keys %{$tmpif}) {
        chomp($tmpif->{$_}) if defined $tmpif->{$_};
      }
      if (defined $self->opts->ifspeed) {
        $tmpif->{ifSpeed} = $self->opts->ifspeed * 1024*1024;
      }
      if (! defined $tmpif->{ifSpeed}) {
        $self->add_unknown(sprintf "There is no /sys/class/net/%s/speed. Use --ifspeed", $name);
      } else {
        push(@{$self->{interfaces}},
          Server::Windows::Component::InterfaceSubsystem::Interface->new(%{$tmpif}));
      }
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking interfaces');
  if (scalar(@{$self->{interfaces}}) == 0) {
    $self->add_unknown('no interfaces');
    return;
  }
  if ($self->mode =~ /device::interfaces::list/) {
    foreach (sort {$a->{ifDescr} cmp $b->{ifDescr}} @{$self->{interfaces}}) {
      $_->list();
    }
  } else {
    foreach (@{$self->{interfaces}}) {
      $_->check();
    }
  }
}


package Server::Windows::Component::InterfaceSubsystem::Interface;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;


sub finish {
  my $self = shift;
  foreach (qw(ifSpeed ifInOctets ifInDiscards ifInErrors ifOutOctets ifOutDiscards ifOutErrors)) {
    $self->{$_} = 0 if ! defined $self->{$_};
  }
  if ($self->mode =~ /device::interfaces::traffic/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInOctets ifInDiscards ifInErrors ifOutOctets ifOutDiscards ifOutErrors));
  } elsif ($self->mode =~ /device::interfaces::usage/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInOctets ifOutOctets));
    if ($self->{ifSpeed} == 0) {
      # vlan graffl
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    } else {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{maxInputRate} = $self->{ifSpeed};
      $self->{maxOutputRate} = $self->{ifSpeed};
    }
    if (defined $self->opts->ifspeedin) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedin);
      $self->{maxInputRate} = $self->opts->ifspeedin;
    }
    if (defined $self->opts->ifspeedout) {
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedout);
      $self->{maxOutputRate} = $self->opts->ifspeedout;
    }
    if (defined $self->opts->ifspeed) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{maxInputRate} = $self->opts->ifspeed;
      $self->{maxOutputRate} = $self->opts->ifspeed;
    }
    $self->{inputRate} = $self->{delta_ifInOctets} / $self->{delta_timestamp};
    $self->{outputRate} = $self->{delta_ifOutOctets} / $self->{delta_timestamp};
    $self->{maxInputRate} /= 8; # auf octets umrechnen wie die in/out
    $self->{maxOutputRate} /= 8;
    my $factor = 1/8; # default Bits
    if ($self->opts->units) {
      if ($self->opts->units eq "GB") {
        $factor = 1024 * 1024 * 1024;
      } elsif ($self->opts->units eq "MB") {
        $factor = 1024 * 1024;
      } elsif ($self->opts->units eq "KB") {
        $factor = 1024;
      } elsif ($self->opts->units eq "GBi") {
        $factor = 1024 * 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "MBi") {
        $factor = 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "KBi") {
        $factor = 1024 / 8;
      } elsif ($self->opts->units eq "B") {
        $factor = 1;
      } elsif ($self->opts->units eq "Bit") {
        $factor = 1/8;
      }
    }
    $self->{inputRate} /= $factor;
    $self->{outputRate} /= $factor;
    $self->{maxInputRate} /= $factor;
    $self->{maxOutputRate} /= $factor;
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInErrors ifOutErrors));
    $self->{inputErrorRate} = $self->{delta_ifInErrors} 
        / $self->{delta_timestamp};
    $self->{outputErrorRate} = $self->{delta_ifOutErrors} 
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInDiscards ifOutDiscards));
    $self->{inputDiscardRate} = $self->{delta_ifInDiscards} 
        / $self->{delta_timestamp};
    $self->{outputDiscardRate} = $self->{delta_ifOutDiscards} 
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::operstatus/) {
  }
  return $self;
}


sub check {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::usage/) {
    $self->add_info(sprintf 'interface %s usage is in:%.2f%% (%s) out:%.2f%% (%s)',
        $self->{ifDescr}, 
        $self->{inputUtilization}, 
        sprintf("%.2f%s/s", $self->{inputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')),
        $self->{outputUtilization},
        sprintf("%.2f%s/s", $self->{outputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')));
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        warning => 80,
        critical => 90
    );
    my $in = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization}
    );
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        warning => 80,
        critical => 90
    );
    my $out = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization}
    );
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization},
        uom => '%',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization},
        uom => '%',
    );

    my ($inwarning, $incritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_in',
        value => $self->{inputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxInputRate},
        warning => $self->{maxInputRate} / 100 * $inwarning,
        critical => $self->{maxInputRate} / 100 * $incritical,
    );
    my ($outwarning, $outcritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_out',
        value => $self->{outputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxOutputRate},
        warning => $self->{maxOutputRate} / 100 * $outwarning,
        critical => $self->{maxOutputRate} / 100 * $outcritical,
    );
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->add_info(sprintf 'interface %s errors in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputErrorRate} , $self->{outputErrorRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputErrorRate});
    my $out = $self->check_thresholds($self->{outputErrorRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_in',
        value => $self->{inputErrorRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_out',
        value => $self->{outputErrorRate},
    );
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->add_info(sprintf 'interface %s discards in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputDiscardRate} , $self->{outputDiscardRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputDiscardRate});
    my $out = $self->check_thresholds($self->{outputDiscardRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_in',
        value => $self->{inputDiscardRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_out',
        value => $self->{outputDiscardRate},
    );
  }
}

sub list {
  my $self = shift;
  printf "%s\n", $self->{ifDescr};
}

package Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-IPSEC-FLOW-MONITOR-MIB', [
      ['ciketunnels', 'cikeTunnelTable', 'Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem::CikeTunnel',  sub { my $o = shift; $o->{parent} = $self; $self->filter_name($o->{cikeTunRemoteValue})}],
  ]);
}

sub check {
  my $self = shift;
  if (! @{$self->{ciketunnels}}) {
    $self->add_critical(sprintf 'tunnel to %s does not exist',
        $self->opts->name);
  } else {
    foreach (@{$self->{ciketunnels}}) {
      $_->check();
    }
  }
}


package Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem::CikeTunnel;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
# cikeTunRemoteValue per --name angegeben, muss active sein
# ansonsten watch-vpns, delta tunnels ueberwachen
  $self->add_info(sprintf 'tunnel to %s is %s',
      $self->{cikeTunRemoteValue}, $self->{cikeTunStatus});
  if ($self->{cikeTunStatus} ne 'active') {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
}

package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{fan_subsystem} =
      Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::FanSubsystem->new();
  $self->{supply_subsystem} =
      Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem->new();
}

sub check {
  my $self = shift;
  $self->{fan_subsystem}->check();
  $self->{supply_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{fan_subsystem}->dump();
  $self->{supply_subsystem}->dump();
}

package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ENTITY-FRU-CONTROL-MIB', [
    ['fans', 'cefcFanTrayStatusTable', 'Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::FanSubsystem::Fan'],
  ]);
  $self->get_snmp_tables('ENTITY-MIB', [
    ['entities', 'entPhysicalTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::PhysicalEntity'],
  ]);
  @{$self->{entities}} = grep { $_->{entPhysicalClass} eq 'fan' } @{$self->{entities}};
  foreach my $fan (@{$self->{fans}}) {
    foreach my $entity (@{$self->{entities}}) {
      if ($fan->{flat_indices} eq $entity->{entPhysicalIndex}) {
        $fan->{entity} = $entity;
      }
    }
  }
}

package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'fan/tray %s%s status is %s',
      $self->{flat_indices},
      #exists $self->{entity} ? ' ('.$self->{entity}->{entPhysicalDescr}.' idx '.$self->{entity}->{entPhysicalIndex}.' class '.$self->{entity}->{entPhysicalClass}.')' : '',
      exists $self->{entity} ? ' ('.$self->{entity}->{entPhysicalDescr}.')' : '',
      $self->{cefcFanTrayOperStatus});
  if ($self->{cefcFanTrayOperStatus} eq "unknown") {
    $self->add_unknown();
  } elsif ($self->{cefcFanTrayOperStatus} eq "down") {
    $self->add_warning();
  } elsif ($self->{cefcFanTrayOperStatus} eq "warning") {
    $self->add_warning();
  }
}

package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ENTITY-FRU-CONTROL-MIB', [
    ['powersupplies', 'cefcFRUPowerStatusTable', 'Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem::Powersupply'],
    ['powersupplygroups', 'cefcFRUPowerSupplyGroupTable', 'Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem::PowersupplyGroup'],
  ]);
  $self->get_snmp_tables('ENTITY-MIB', [
    ['entities', 'entPhysicalTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::PhysicalEntity'],
  ]);
  @{$self->{entities}} = grep { $_->{entPhysicalClass} eq 'powerSupply' } @{$self->{entities}};
  foreach my $supply (@{$self->{supplies}}) {
    foreach my $entity (@{$self->{entities}}) {
      if ($supply->{flat_indices} eq $entity->{entPhysicalIndex}) {
        $supply->{entity} = $entity;
      }
    }
  }
}


package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem::Powersupply;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'power supply %s%s admin status is %s, oper status is %s',
      $self->{flat_indices},
      #exists $self->{entity} ? ' ('.$self->{entity}->{entPhysicalDescr}.' idx '.$self->{entity}->{entPhysicalIndex}.' class '.$self->{entity}->{entPhysicalClass}.')' : '',
      exists $self->{entity} ? ' ('.$self->{entity}->{entPhysicalDescr}.' )' : '',
      $self->{cefcFRUPowerAdminStatus},
      $self->{cefcFRUPowerOperStatus});
return;
  if ($self->{cefcSupplyTrayOperStatus} eq "on") {
  } elsif ($self->{cefcSupplyTrayOperStatus} eq "onButFanFail") {
    $self->add_warning();
  } else {
    $self->add_critical();
  }
}


package Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::PowersupplySubsystem::PowersupplyGroup;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;


package Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $sensors = {};
  $self->get_snmp_tables('CISCO-ENTITY-SENSOR-MIB', [
    ['sensors', 'entSensorValueTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::Sensor', sub { my $o = shift; $self->filter_name($o->{entPhysicalIndex})}],
    ['thresholds', 'entSensorThresholdTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::SensorThreshold'],
  ]);
  $self->get_snmp_tables('ENTITY-MIB', [
    ['entities', 'entPhysicalTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::PhysicalEntity'],
  ]);
  @{$self->{sensor_entities}} = grep { $_->{entPhysicalClass} eq 'sensor' } @{$self->{entities}};
  foreach my $sensor (@{$self->{sensors}}) {
    $sensors->{$sensor->{entPhysicalIndex}} = $sensor;
    foreach my $threshold (@{$self->{thresholds}}) {
      if ($sensor->{entPhysicalIndex} eq $threshold->{entPhysicalIndex}) {
        push(@{$sensor->{thresholds}}, $threshold);
      }
    }
    foreach my $entity (@{$self->{sensor_entities}}) {
      if ($sensor->{entPhysicalIndex} eq $entity->{entPhysicalIndex}) {
        $sensor->{entity} = $entity;
      }
    }
  }
}

package Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub finish {
  my $self = shift;
  $self->{entPhysicalIndex} = $self->{flat_indices};
  # www.thaiadmin.org%2Fboard%2Findex.php%3Faction%3Ddlattach%3Btopic%3D45832.0%3Battach%3D23494&ei=kV9zT7GHJ87EsgbEvpX6DQ&usg=AFQjCNHuHiS2MR9TIpYtu7C8bvgzuqxgMQ&cad=rja
  # zu klaeren. entPhysicalIndex entspricht dem entPhysicalindex der ENTITY-MIB.
  # In der stehen alle moeglichen Powersupplies etc.
  # Was bedeutet aber dann entSensorMeasuredEntity? gibt's eh nicht in meinen
  # Beispiel-walks
  $self->{thresholds} = [];
  $self->{entSensorMeasuredEntity} ||= 'undef';
}

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s sensor %s%s is %s',
      $self->{entSensorType},
      $self->{entPhysicalIndex},
      exists $self->{entity} ? ' ('.$self->{entity}->{entPhysicalDescr}.')' : '',
      $self->{entSensorStatus});
  if ($self->{entSensorStatus} eq "nonoperational") {
    $self->add_critical();
  } elsif ($self->{entSensorStatus} eq "unknown_10") {
    # these sensors do not exist according to cisco-tools
    return;
  } elsif ($self->{entSensorStatus} eq "unavailable") {
    return;
  }
  my $label = sprintf('sens_%s_%s', $self->{entSensorType}, $self->{entPhysicalIndex});
  my $warningx = ($self->get_thresholds(metric => $label))[0];
  my $criticalx = ($self->get_thresholds(metric => $label))[1];
  if (scalar(@{$self->{thresholds}} == 2)) {
    # reparaturlauf
    foreach my $idx (0..1) {
      my $otheridx = $idx == 0 ? 1 : 0;
      if (! defined @{$self->{thresholds}}[$idx]->{entSensorThresholdSeverity} &&   
          @{$self->{thresholds}}[$otheridx]->{entSensorThresholdSeverity} eq "minor") {
        @{$self->{thresholds}}[$idx]->{entSensorThresholdSeverity} = "major";
      } elsif (! defined @{$self->{thresholds}}[$idx]->{entSensorThresholdSeverity} &&   
          @{$self->{thresholds}}[$otheridx]->{entSensorThresholdSeverity} eq "minor") {
        @{$self->{thresholds}}[$idx]->{entSensorThresholdSeverity} = "minor";
      }
    }
    my $warning = (map { $_->{entSensorThresholdValue} } 
        grep { $_->{entSensorThresholdSeverity} eq "minor" }
        @{$self->{thresholds}})[0];
    my $critical = (map { $_->{entSensorThresholdValue} } 
        grep { $_->{entSensorThresholdSeverity} eq "major" }
        @{$self->{thresholds}})[0];
    $self->set_thresholds(
        metric => $label,
        warning => $warning, critical => $critical
    );
    if ((defined($criticalx) && 
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == CRITICAL) ||
        (! defined($criticalx) && 
            grep { $_->{entSensorThresholdEvaluation} eq "true" } 
            grep { $_->{entSensorThresholdSeverity} eq "major" } @{$self->{thresholds}})) {
      # eigener schwellwert hat vorrang
      $self->add_critical(sprintf "%s sensor %s threshold evaluation is true (value: %s, major threshold: %s)", 
          $self->{entSensorType},
          $self->{entPhysicalIndex},
          $self->{entSensorValue},
          defined($criticalx) ? $criticalx : $critical
      );
    } elsif ((defined($warningx) && 
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == WARNING) ||
        (! defined($warningx) && 
            grep { $_->{entSensorThresholdEvaluation} eq "true" } 
            grep { $_->{entSensorThresholdSeverity} eq "minor" } @{$self->{thresholds}})) {
      $self->add_warning(sprintf "%s sensor %s threshold evaluation is true (value: %s, minor threshold: %s)", 
          $self->{entSensorType},
          $self->{entPhysicalIndex},
          $self->{entSensorValue},
          defined($warningx) ? $warningx : $warning
      );
    }
    $self->add_perfdata(
        label => $label,
        value => $self->{entSensorValue},
        warning => defined($warningx) ? $warningx : $warning,
        critical => defined($criticalx) ? $criticalx : $critical,
    );
  } elsif ($self->{entSensorValue}) {
    if ((defined($criticalx) && 
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == CRITICAL) ||
       (defined($warningx) && 
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == WARNING) ||
       ($self->{entSensorThresholdEvaluation} && $self->{entSensorThresholdEvaluation} eq "true")) {
    }
    if (defined($criticalx) &&
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == CRITICAL) {
      $self->add_critical(sprintf "%s sensor %s threshold evaluation is true (value: %s)",
          $self->{entSensorType},
          $self->{entPhysicalIndex},
          $self->{entSensorValue}
      );
      $self->add_perfdata(
          label => $label,
          value => $self->{entSensorValue},
          critical => $criticalx,
          warning => $warningx,
      );
    } elsif (defined($warningx) &&
        $self->check_thresholds(metric => $label, value => $self->{entSensorValue}) == WARNING) {
      $self->add_warning(sprintf "%s sensor %s threshold evaluation is true (value: %s)",
          $self->{entSensorType},
          $self->{entPhysicalIndex},
          $self->{entSensorValue}
      );
      $self->add_perfdata(
          label => $label,
          value => $self->{entSensorValue},
          critical => $criticalx,
          warning => $warningx,
      );
    } elsif ($self->{entSensorThresholdEvaluation} && $self->{entSensorThresholdEvaluation} eq "true") {
      $self->add_warning(sprintf "%s sensor %s threshold evaluation is true (value: %s)",
          $self->{entSensorType},
          $self->{entPhysicalIndex},
          $self->{entSensorValue}
      );
      $self->add_perfdata(
          label => $label,
          value => $self->{entSensorValue},
          warning => $self->{ciscoEnvMonSensorThreshold},
      );
    }
  } elsif (scalar(grep { $_->{entSensorThresholdEvaluation} eq "true" }
      @{$self->{thresholds}})) {
    $self->add_warning(sprintf "%s sensor %s threshold evaluation is true", 
        $self->{entSensorType},
        $self->{entPhysicalIndex});
  }
}


package Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::SensorThreshold;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{entPhysicalIndex} = $self->{indices}->[0];
  $self->{entSensorThresholdIndex} = $self->{indices}->[1];
}


package Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem::PhysicalEntity;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{entPhysicalIndex} = $self->{flat_indices};
}



package Classes::Cisco::CISCOENTITYALARMMIB::Component::AlarmSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $alarms = {};
  $self->get_snmp_tables('CISCO-ENTITY-ALARM-MIB', [
    ['alarms', 'ceAlarmTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::Alarm', sub { my $o = shift; $o->{parent} = $self; $self->filter_name($o->{entPhysicalIndex})}],
    ['alarmdescriptionmappings', 'ceAlarmDescrMapTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmDescriptionMapping' ],
    ['alarmdescriptions', 'ceAlarmDescrTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmDescription' ],
    ['alarmfilterprofiles', 'ceAlarmFilterProfileTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmFilterProfile' ],
    ['alarmhistory', 'ceAlarmHistTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmHistory', sub { my $o = shift; $o->{parent} = $self; $self->filter_name($o->{entPhysicalIndex})}],
  ]);
  $self->get_snmp_tables('ENTITY-MIB', [
    ['entities', 'entPhysicalTable', 'Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::PhysicalEntity'],
  ]);
  $self->get_snmp_objects('CISCO-ENTITY-ALARM-MIB', qw(
      ceAlarmCriticalCount ceAlarmMajorCount ceAlarmMinorCount
      ceAlarmFilterProfileIndexNext
  ));
  foreach (qw(ceAlarmCriticalCount ceAlarmMajorCount ceAlarmMinorCount)) {
    $self->{$_} ||= 0;
  }
  @{$self->{alarms}} = grep { 
      $_->{ceAlarmSeverity} ne 'none' &&
      $_->{ceAlarmSeverity} ne 'info'
  } @{$self->{alarms}};
  foreach my $alarm (@{$self->{alarms}}) {
    foreach my $entity (@{$self->{entities}}) {
      if ($alarm->{entPhysicalIndex} eq $entity->{entPhysicalIndex}) {
        $alarm->{entity} = $entity;
      }
    }
  }
}

sub check {
  my $self = shift;
  if (scalar(@{$self->{alarms}}) == 0) {
    $self->add_info('no alarms');
    $self->add_ok();
  } else {
    foreach (@{$self->{alarms}}) {
      $_->check();
    }
    foreach (@{$self->{alarmhistory}}) {
      $_->check();
    }
    if (! $self->check_messages()) { # blacklisted des ganze glump
      $self->add_info('no alarms');
      $self->add_ok();
    }
  }
}

package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::Alarm;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{entPhysicalIndex} = $self->{flat_indices};
  $self->{ceAlarmTypes} = [];
  if ($self->{ceAlarmList}) {
    my $index = 0;
    foreach my $octet (split(/\s+/, $self->{ceAlarmList})) {
      my $hexoctet = hex($octet) & 0xff;
      if ($hexoctet) {
        my $base = 8 * $index;
        foreach my $bit (0..7) {
          my $mask = (2 ** $bit) & 0xff;
          if ($hexoctet & $mask) {
            push(@{$self->{ceAlarmTypes}}, $base + $bit);
          }
        }
      }
      $index++;
    }
  }
  $self->{ceAlarmTypes} = join(",", @{$self->{ceAlarmTypes}}); # weil sonst der drecks-dump nicht funktioniert.
}

sub check {
  my $self = shift;
  my $location = exists $self->{entity} ?
      $self->{entity}->{entPhysicalDescr} : "unknown";
  if (length($self->{ceAlarmTypes})) {
    my @descriptorindexes = map {
        $_->{ceAlarmDescrIndex}
    } grep {
        $self->{entity}->{entPhysicalVendorType} eq $_->{ceAlarmDescrVendorType}
    } @{$self->{parent}->{alarmdescriptionmappings}};
    if (@descriptorindexes) {
      my $ceAlarmDescrIndex = $descriptorindexes[0];
      my @descriptions = grep {
        $_->{ceAlarmDescrIndex} == $ceAlarmDescrIndex;
      } @{$self->{parent}->{alarmdescriptions}};
      foreach my $ceAlarmType (split(",", $self->{ceAlarmTypes})) {
        foreach my $alarmdesc (@descriptions) {
          if ($alarmdesc->{ceAlarmDescrAlarmType} == $ceAlarmType) {
            $self->add_info(sprintf "%s alarm '%s' in entity %d (%s)",
                $alarmdesc->{ceAlarmDescrSeverity},
                $alarmdesc->{ceAlarmDescrText},
                $self->{entPhysicalIndex},
                $location);
            if ($alarmdesc->{ceAlarmDescrSeverity} eq "none") {
              # A value of '0' indicates that there the corresponding physical entity currently is not asserting any alarms.
            } elsif ($alarmdesc->{ceAlarmDescrSeverity} eq "critical") {
              $self->add_critical();
            } elsif ($alarmdesc->{ceAlarmDescrSeverity} eq "major") {
              $self->add_critical();
            } elsif ($alarmdesc->{ceAlarmDescrSeverity} eq "minor") {
              $self->add_warning();
            } elsif ($alarmdesc->{ceAlarmDescrSeverity} eq "info") {
              $self->add_ok();
            }
          }
        }
      }
    }
  }
  delete $self->{parent}; # brauch ma nimmer, daad eh sched bon dump scheebern
}


package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::PhysicalEntity;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{entPhysicalIndex} = $self->{flat_indices};
}

package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmDescription;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

sub finish {
  my $self = shift;
  $self->{ceAlarmDescrIndex} = $self->{indices}->[0];
  $self->{ceAlarmDescrAlarmType} = $self->{indices}->[1];
}


package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmDescriptionMapping;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

sub finish {
  my $self = shift;
  $self->{ceAlarmDescrIndex} = $self->{indices}->[0];
}

package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmFilterProfile;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

package Classes::Cisco::CISCOENTITYSENSORMIB::Component::AlarmSubsystem::AlarmHistory;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

sub finish {
  my $self = shift;
  $self->{ceAlarmHistTimeStamp} = time - $self->uptime() + $self->timeticks($self->{ceAlarmHistTimeStamp});
  $self->{ceAlarmHistTimeStampLocal} = scalar localtime $self->{ceAlarmHistTimeStamp};
}

sub check {
  my $self = shift;
  my $vendortype = "unknown";
  my @entities = grep {
    $_->{entPhysicalIndex} == $self->{ceAlarmHistEntPhysicalIndex};
  } @{$self->{parent}->{entities}};
  if (@entities) {
    $vendortype = $entities[0]->{entPhysicalVendorType};
    $self->{ceAlarmHistEntPhysicalDescr} = $entities[0]->{entPhysicalDescr};
  }
  my @descriptorindexes = map {
      $_->{ceAlarmDescrIndex}
  } grep {
      $vendortype eq $_->{ceAlarmDescrVendorType}
  } @{$self->{parent}->{alarmdescriptionmappings}};
  if (@descriptorindexes) {
    my $ceAlarmDescrIndex = $descriptorindexes[0];
    my @descriptions = grep {
      $_->{ceAlarmDescrIndex} == $ceAlarmDescrIndex;
    } @{$self->{parent}->{alarmdescriptions}};
    foreach my $alarmdesc (@descriptions) {
      if ($alarmdesc->{ceAlarmDescrAlarmType} == $self->{ceAlarmHistAlarmType}) {
        $self->{ceAlarmHistAlarmDescrText} = $alarmdesc->{ceAlarmDescrText};
      }
    }
  }
  delete $self->{parent};
}

package Classes::Cisco::CISCOENVMONMIB::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ENVMON-MIB', [
      ['temperatures', 'ciscoEnvMonTemperatureStatusTable', 'Classes::Cisco::CISCOENVMONMIB::Component::TemperatureSubsystem::Temperature'],
  ]);
}

package Classes::Cisco::CISCOENVMONMIB::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {};
  foreach (keys %params) {
    $self->{$_} = $params{$_};
  }
  if ($self->{ciscoEnvMonTemperatureStatusValue}) {
    bless $self, $class;
  } else {
    bless $self, $class.'::Simple';
  }
  $self->ensure_index('ciscoEnvMonTemperatureStatusIndex');
  $self->{ciscoEnvMonTemperatureLastShutdown} ||= 0;
  return $self;
}

sub check {
  my $self = shift;
  if ($self->{ciscoEnvMonTemperatureStatusValue} >
      $self->{ciscoEnvMonTemperatureThreshold}) {
    $self->add_info(sprintf 'temperature %d %s is too high (%d of %d max = %s)',
        $self->{ciscoEnvMonTemperatureStatusIndex},
        $self->{ciscoEnvMonTemperatureStatusDescr},
        $self->{ciscoEnvMonTemperatureStatusValue},
        $self->{ciscoEnvMonTemperatureThreshold},
        $self->{ciscoEnvMonTemperatureState});
    if ($self->{ciscoEnvMonTemperatureState} eq 'warning') {
      $self->add_warning();
    } elsif ($self->{ciscoEnvMonTemperatureState} eq 'critical') {
      $self->add_critical();
    }
  } else {
    $self->add_info(sprintf 'temperature %d %s is %d (of %d max = normal)',
        $self->{ciscoEnvMonTemperatureStatusIndex},
        $self->{ciscoEnvMonTemperatureStatusDescr},
        $self->{ciscoEnvMonTemperatureStatusValue},
        $self->{ciscoEnvMonTemperatureThreshold},
        $self->{ciscoEnvMonTemperatureState});
  }
  $self->add_perfdata(
      label => sprintf('temp_%s', $self->{ciscoEnvMonTemperatureStatusIndex}),
      value => $self->{ciscoEnvMonTemperatureStatusValue},
      warning => $self->{ciscoEnvMonTemperatureThreshold},
      critical => undef,
  );
}


package Classes::Cisco::CISCOENVMONMIB::Component::TemperatureSubsystem::Temperature::Simple;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{ciscoEnvMonTemperatureStatusIndex} ||= 0;
  $self->{ciscoEnvMonTemperatureStatusDescr} ||= 0;
  $self->add_info(sprintf 'temperature %d %s is %s',
      $self->{ciscoEnvMonTemperatureStatusIndex},
      $self->{ciscoEnvMonTemperatureStatusDescr},
      $self->{ciscoEnvMonTemperatureState});
  if ($self->{ciscoEnvMonTemperatureState} ne 'normal') {
    if ($self->{ciscoEnvMonTemperatureState} eq 'warning') {
      $self->add_warning();
    } elsif ($self->{ciscoEnvMonTemperatureState} eq 'critical') {
      $self->add_critical();
    }
  } else {
  }
}

package Classes::Cisco::CISCOENVMONMIB::Component::PowersupplySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ENVMON-MIB', [
      ['supplies', 'ciscoEnvMonSupplyStatusTable', 'Classes::Cisco::CISCOENVMONMIB::Component::PowersupplySubsystem::Powersupply'],
  ]);
}

package Classes::Cisco::CISCOENVMONMIB::Component::PowersupplySubsystem::Powersupply;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->ensure_index('ciscoEnvMonSupplyStatusIndex');
  $self->add_info(sprintf 'powersupply %d (%s) is %s',
      $self->{ciscoEnvMonSupplyStatusIndex},
      $self->{ciscoEnvMonSupplyStatusDescr},
      $self->{ciscoEnvMonSupplyState});
  if ($self->{ciscoEnvMonSupplyState} eq 'notPresent') {
  } elsif ($self->{ciscoEnvMonSupplyState} eq 'warning') {
    $self->add_warning();
  } elsif ($self->{ciscoEnvMonSupplyState} ne 'normal') {
    $self->add_critical();
  }
}

package Classes::Cisco::CISCOENVMONMIB::Component::VoltageSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $index = 0;
  $self->get_snmp_tables('CISCO-ENVMON-MIB', [
      ['voltages', 'ciscoEnvMonVoltageStatusTable', 'Classes::Cisco::CISCOENVMONMIB::Component::VoltageSubsystem::Voltage'],
  ]);
}

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking voltages');
  if (scalar (@{$self->{voltages}}) == 0) {
  } else {
    foreach (@{$self->{voltages}}) {
      $_->check();
    }
  }
}


package Classes::Cisco::CISCOENVMONMIB::Component::VoltageSubsystem::Voltage;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->ensure_index('ciscoEnvMonVoltageStatusIndex');
  $self->add_info(sprintf 'voltage %d (%s) is %s',
      $self->{ciscoEnvMonVoltageStatusIndex},
      $self->{ciscoEnvMonVoltageStatusDescr},
      $self->{ciscoEnvMonVoltageState});
  if ($self->{ciscoEnvMonVoltageState} eq 'notPresent') {
  } elsif ($self->{ciscoEnvMonVoltageState} ne 'normal') {
    $self->add_critical();
  }
  $self->add_perfdata(
      label => sprintf('mvolt_%s', $self->{ciscoEnvMonVoltageStatusIndex}),
      value => $self->{ciscoEnvMonVoltageStatusValue},
      warning => $self->{ciscoEnvMonVoltageThresholdLow},
      critical => $self->{ciscoEnvMonVoltageThresholdHigh},
  );
}

package Classes::Cisco::CISCOENVMONMIB::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ENVMON-MIB', [
      ['fans', 'ciscoEnvMonFanStatusTable', 'Classes::Cisco::CISCOENVMONMIB::Component::FanSubsystem::Fan'],
  ]);
}

package Classes::Cisco::CISCOENVMONMIB::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->ensure_index('ciscoEnvMonFanStatusIndex');
  $self->add_info(sprintf 'fan %d (%s) is %s',
      $self->{ciscoEnvMonFanStatusIndex},
      $self->{ciscoEnvMonFanStatusDescr},
      $self->{ciscoEnvMonFanState});
  if ($self->{ciscoEnvMonFanState} eq 'notPresent') {
  } elsif ($self->{ciscoEnvMonFanState} ne 'normal') {
    $self->add_critical();
  }
}

package Classes::Cisco::ASA;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::CISCOENTITYALARMMIB::Component::AlarmSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::IOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::IOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::hsrp/) {
    $self->analyze_and_check_hsrp_subsystem("Classes::HSRP::Component::HSRPSubsystem");
  } elsif ($self->mode =~ /device::users/) {
    $self->analyze_and_check_connection_subsystem("Classes::Cisco::IOS::Component::ConnectionSubsystem");
  } elsif ($self->mode =~ /device::config/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::ConfigSubsystem");
  } elsif ($self->mode =~ /device::interfaces::nat::sessions::count/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::NatSubsystem");
  } elsif ($self->mode =~ /device::interfaces::nat::rejects/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::NatSubsystem");
  } elsif ($self->mode =~ /device::vpn::status/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::CISCOIPSECFLOWMONITOR::Component::VpnSubsystem");
  } else {
    $self->no_such_mode();
  }
}


package Classes::Cisco::IOS::Component::ConfigSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CISCO-CONFIG-MAN-MIB', (qw(
      ccmHistoryRunningLastChanged ccmHistoryRunningLastSaved
      ccmHistoryStartupLastChanged)));
  foreach ((qw(ccmHistoryRunningLastChanged ccmHistoryRunningLastSaved
      ccmHistoryStartupLastChanged))) {
    if (! defined $self->{$_}) {
      $self->add_unknown(sprintf "%s is not defined", $_);
    }
    $self->{$_} = time - $self->uptime() + $self->timeticks($self->{$_});
  }
}

sub check {
  my $self = shift;
  my $info;
  $self->add_info('checking config');
  if ($self->check_messages()) {
    return;
  }
  # ccmHistoryRunningLastChanged
  # ccmHistoryRunningLastSaved - saving is ANY write (local/remote storage, terminal)
  # ccmHistoryStartupLastChanged 
  $self->set_thresholds(warning => 3600, critical => 3600*24);

  # how much is ccmHistoryRunningLastChanged ahead of ccmHistoryRunningLastSaved
  # the current running config is definitively lost in case of an outage
  my $unsaved_since =
      $self->{ccmHistoryRunningLastChanged} > $self->{ccmHistoryRunningLastSaved} ?
      time - $self->{ccmHistoryRunningLastChanged} : 0;

  # how much is ccmHistoryRunningLastSaved ahead of ccmHistoryStartupLastChanged
  # the running config could have been saved for backup purposes.
  # the saved config can still be identical to the saved running config
  # if there are regular backups of the running config and no one messes
  # with the latter without flushing it to the startup config, then i recommend
  # to use --mitigation ok. this can be in an environment, where there is
  # a specific day of the week reserved for maintenance and admins are forced
  # to save their modifications to the startup-config.
  my $unsynced_since = 
      $self->{ccmHistoryRunningLastSaved} > $self->{ccmHistoryStartupLastChanged} ? 
      time - $self->{ccmHistoryRunningLastSaved} : 0;
  if ($unsaved_since) {
    $self->add_info(sprintf "running config is modified and unsaved since %d minutes. your changes my be lost in case of a reboot",
        $unsaved_since / 60);
  } else {
    $self->add_info("saved config is up to date");
  }
  $self->add_message($self->check_thresholds($unsaved_since));
  if ($unsynced_since) {
    my $errorlevel = defined $self->opts->mitigation() ?
        $self->opts->mitigation() :
        $self->check_thresholds($unsynced_since);
    $self->add_info(sprintf "saved running config is ahead of startup config since %d minutes. device will boot with a config different from the one which was last saved",
        $unsynced_since / 60);
    $self->add_message($self->check_thresholds($unsaved_since));
  }
}

package Classes::Cisco::IOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;
use constant PHYS_NAME => 1;
use constant PHYS_ASSET => 2;
use constant PHYS_DESCR => 4;

{
  our $cpmCPUTotalIndex = 0;
  our $uniquify = PHYS_NAME;
}

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-PROCESS-MIB', [
      ['cpus', 'cpmCPUTotalTable', 'Classes::Cisco::IOS::Component::CpuSubsystem::Cpu' ],
  ]);
  if (scalar(@{$self->{cpus}}) == 0) {
    # maybe too old. i fake a cpu. be careful. this is a really bad hack
    my $response = $self->get_request(
        -varbindlist => [
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1},
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5},
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{busyPer},
        ]
    );
    if (exists $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}}) {
      push(@{$self->{cpus}},
          Classes::Cisco::IOS::Component::CpuSubsystem::Cpu->new(
              cpmCPUTotalPhysicalIndex => 0, #fake
              cpmCPUTotalIndex => 0, #fake
              cpmCPUTotal5sec => 0, #fake
              cpmCPUTotal5secRev => 0, #fake
              cpmCPUTotal1min => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}},
              cpmCPUTotal1minRev => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}},
              cpmCPUTotal5min => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5}},
              cpmCPUTotal5minRev => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5}},
              cpmCPUMonInterval => 0, #fake
              cpmCPUTotalMonIntervalValue => 0, #fake
              cpmCPUInterruptMonIntervalValue => 0, #fake
      ));
    }
  }
  # same cpmCPUTotalPhysicalIndex found in multiple table rows
  if (scalar(@{$self->{cpus}}) > 1) {
    my %names = ();
    foreach my $cpu (@{$self->{cpus}}) {
      $names{$cpu->{name}}++;
    }
    foreach my $cpu (@{$self->{cpus}}) {
      if ($names{$cpu->{name}} > 1) {
        # more than one cpu points to the same physical entity
        $cpu->{name} .= '.'.$cpu->{flat_indices};
      }
    }
  }
}

package Classes::Cisco::IOS::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{cpmCPUTotalIndex} = $self->{flat_indices};
  $self->{cpmCPUTotalPhysicalIndex} = exists $self->{cpmCPUTotalPhysicalIndex} ?
      $self->{cpmCPUTotalPhysicalIndex} : 0;
  if (exists $self->{cpmCPUTotal5minRev}) {
    $self->{usage} = $self->{cpmCPUTotal5minRev};
  } else {
    $self->{usage} = $self->{cpmCPUTotal5min};
  }
  $self->protect_value($self->{cpmCPUTotalIndex}.$self->{cpmCPUTotalPhysicalIndex}, 'usage', 'percent');
  if ($self->{cpmCPUTotalPhysicalIndex}) {
    $self->{entPhysicalName} = $self->get_snmp_object('ENTITY-MIB', 'entPhysicalName', $self->{cpmCPUTotalPhysicalIndex});
    # wichtig fuer gestacktes zeugs, bei dem entPhysicalName doppelt und mehr vorkommen kann
    # This object is a user-assigned asset tracking identifier for the physical entity
    # as specified by a network manager, and provides non-volatile storage of this
    # information. On the first instantiation of an physical entity, the value of
    # entPhysicalAssetID associated with that entity is set to the zero-length string.
    # ...
    # If write access is implemented for an instance of entPhysicalAssetID, and a value
    # is written into the instance, the agent must retain the supplied value in the
    # entPhysicalAssetID instance associated with the same physical entity for as long
    # as that entity remains instantiated. This includes instantiations across all
    # re-initializations/reboots of the network management system, including those
    # which result in a change of the physical entity's entPhysicalIndex value.
    $self->{entPhysicalAssetID} = $self->get_snmp_object('ENTITY-MIB', 'entPhysicalAssetID', $self->{cpmCPUTotalPhysicalIndex});
    $self->{entPhysicalDescr} = $self->get_snmp_object('ENTITY-MIB', 'entPhysicalDescr', $self->{cpmCPUTotalPhysicalIndex});
    $self->{name} = $self->{entPhysicalName} || $self->{entPhysicalDescr};
  } else {
    $self->{name} = $self->{cpmCPUTotalIndex};
    # waere besser, aber dann zerlegts wohl zu viele rrdfiles
    #$self->{name} = 'central processor';
  }
  return $self;
}

sub check {
  my $self = shift;
  $self->{label} = $self->{name};
  $self->add_info(sprintf 'cpu %s usage (5 min avg.) is %.2f%%',
      $self->{name}, $self->{usage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{usage}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{label}.'_usage',
      value => $self->{usage},
      uom => '%',
  );
}

package Classes::Cisco::IOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-MEMORY-POOL-MIB', [
      ['mems', 'ciscoMemoryPoolTable', 'Classes::Cisco::IOS::Component::MemSubsystem::Mem'],
  ]);
}

package Classes::Cisco::IOS::Component::MemSubsystem::Mem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{usage} = 100 * $self->{ciscoMemoryPoolUsed} /
      ($self->{ciscoMemoryPoolFree} + $self->{ciscoMemoryPoolUsed});
}

sub check {
  my $self = shift;
  $self->{ciscoMemoryPoolType} ||= 0;
  $self->add_info(sprintf 'mempool %s usage is %.2f%%',
      $self->{ciscoMemoryPoolName}, $self->{usage});
  if ($self->{ciscoMemoryPoolName} eq 'lsmpi_io' && 
      $self->get_snmp_object('MIB-II', 'sysDescr', 0) =~ /IOS.*XE/i) {
    # https://supportforums.cisco.com/docs/DOC-16425
    $self->force_thresholds(
        metric => $self->{ciscoMemoryPoolName}.'_usage',
        warning => 100,
        critical => 100,
    );
  } elsif ($self->{ciscoMemoryPoolName} eq 'reserved' && 
      $self->get_snmp_object('MIB-II', 'sysDescr', 0) =~ /IOS.*XR/i) {
    # ASR9K "reserved" and "image" are always at 100%
    $self->force_thresholds(
        metric => $self->{ciscoMemoryPoolName}.'_usage',
        warning => 100,
        critical => 100,
    );
  } elsif ($self->{ciscoMemoryPoolName} eq 'image' && 
      $self->get_snmp_object('MIB-II', 'sysDescr', 0) =~ /IOS.*XR/i) {
    $self->force_thresholds(
        metric => $self->{ciscoMemoryPoolName}.'_usage',
        warning => 100,
        critical => 100,
    );
  } else {
    $self->set_thresholds(
        metric => $self->{ciscoMemoryPoolName}.'_usage',
        warning => 80,
        critical => 90,
    );
  }
  $self->add_message($self->check_thresholds(
      metric => $self->{ciscoMemoryPoolName}.'_usage',
      value => $self->{usage},
  ));
  $self->add_perfdata(
      label => $self->{ciscoMemoryPoolName}.'_usage',
      value => $self->{usage},
      uom => '%',
  );
}

package Classes::Cisco::IOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  #
  # 1.3.6.1.4.1.9.9.13.1.1.0 ciscoEnvMonPresent (irgendein typ of envmon)
  # 
  $self->get_snmp_objects('CISCO-ENVMON-MIB', qw(
      ciscoEnvMonPresent));
  if (! $self->{ciscoEnvMonPresent}) {
    # gibt IOS-Kisten, die haben kein ciscoEnvMonPresent
    $self->{ciscoEnvMonPresent} = $self->implements_mib('CISCO-ENVMON-MIB');
  }
  if ($self->{ciscoEnvMonPresent} && 
      $self->{ciscoEnvMonPresent} ne 'oldAgs') {
    $self->{fan_subsystem} =
        Classes::Cisco::CISCOENVMONMIB::Component::FanSubsystem->new();
    $self->{temperature_subsystem} =
        Classes::Cisco::CISCOENVMONMIB::Component::TemperatureSubsystem->new();
    $self->{powersupply_subsystem} = 
        Classes::Cisco::CISCOENVMONMIB::Component::PowersupplySubsystem->new();
    $self->{voltage_subsystem} =
        Classes::Cisco::CISCOENVMONMIB::Component::VoltageSubsystem->new();
  } elsif ($self->implements_mib('CISCO-ENTITY-SENSOR-MIB')) {
    # (IOS can have ENVMON+ENTITY. Sensors are copies, so not needed)
    $self->{sensor_subsystem} =
        Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem->new();
  } elsif ($self->get_snmp_object('MIB-II', 'sysDescr', 0) =~ /C1700 Software/) {
    $self->add_ok("environmental hardware working fine");
    $self->add_ok('soho device, hopefully too small to fail');
  } else {
    # last hope
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::CISCOENTITYALARMMIB::Component::AlarmSubsystem");
    #$self->no_such_mode();
  }
}

sub check {
  my $self = shift;
  if ($self->{ciscoEnvMonPresent}) {
    $self->{fan_subsystem}->check();
    $self->{temperature_subsystem}->check();
    $self->{voltage_subsystem}->check();
    $self->{powersupply_subsystem}->check();
  } elsif ($self->{ciscoEntitySensorPresent}) {
    $self->{sensor_subsystem}->check();
  }
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  if ($self->{ciscoEnvMonPresent}) {
    $self->{fan_subsystem}->dump();
    $self->{temperature_subsystem}->dump();
    $self->{voltage_subsystem}->dump();
    $self->{powersupply_subsystem}->dump();
  } elsif ($self->{ciscoEntitySensorPresent}) {
    $self->{sensor_subsystem}->dump();
  }
}

package Classes::Cisco::IOS::Component::ConnectionSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-FIREWALL-MIB', [
      ['connectionstates', 'cfwConnectionStatTable', 'Classes::Cisco::IOS::Component::ConnectionSubsystem::ConnectionState'],
  ]);
}

package Classes::Cisco::IOS::Component::ConnectionSubsystem::ConnectionState;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  if ($self->{cfwConnectionStatDescription} !~ /number of connections currently in use/i) {
    $self->add_blacklist(sprintf 'c:%s', $self->{cfwConnectionStatDescription});
    $self->add_info(sprintf '%d connections currently in use',
        $self->{cfwConnectionStatValue}||$self->{cfwConnectionStatCount}, $self->{usage});
  } else {
    $self->add_info(sprintf '%d connections currently in use',
        $self->{cfwConnectionStatValue}, $self->{usage});
    $self->set_thresholds(warning => 500000, critical => 750000);
    $self->add_message($self->check_thresholds($self->{cfwConnectionStatValue}));
    $self->add_perfdata(
        label => 'connections',
        value => $self->{cfwConnectionStatValue},
    );
  }
}

package Classes::Cisco::IOS::Component::NatSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::nat::sessions::count/) { 
    $self->get_snmp_objects('CISCO-IETF-NAT-MIB', qw(
        cnatAddrBindNumberOfEntries cnatAddrPortBindNumberOfEntries
    ));
  } elsif ($self->mode =~ /device::interfaces::nat::rejects/) { 
    $self->get_snmp_tables('CISCO-IETF-NAT-MIB', [
        ['protocolstats', 'cnatProtocolStatsTable', 'Classes::Cisco::IOS::Component::NatSubsystem::CnatProtocolStats'],
    ]);
  }
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::nat::sessions::count/) { 
    $self->add_info(sprintf '%d bind entries (%d addr, %d port)',
        $self->{cnatAddrBindNumberOfEntries} + $self->{cnatAddrPortBindNumberOfEntries},
        $self->{cnatAddrBindNumberOfEntries},
        $self->{cnatAddrPortBindNumberOfEntries}
    );
    $self->add_ok();
    $self->add_perfdata(
        label => 'nat_bindings',
        value => $self->{cnatAddrBindNumberOfEntries} + $self->{cnatAddrPortBindNumberOfEntries},
    );
    $self->add_perfdata(
        label => 'nat_addr_bindings',
        value => $self->{cnatAddrBindNumberOfEntries},
    );
    $self->add_perfdata(
        label => 'nat_port_bindings',
        value => $self->{cnatAddrPortBindNumberOfEntries},
    );
  } elsif ($self->mode =~ /device::interfaces::nat::rejects/) {
    foreach (@{$self->{protocolstats}}) {
      $_->check();
    }
  }
}

package Classes::Cisco::IOS::Component::NatSubsystem::CnatProtocolStats;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{cnatProtocolStatsName} = $self->{flat_indices};
  $self->make_symbolic('CISCO-IETF-NAT-MIB', 'cnatProtocolStatsName', $self->{cnatProtocolStatsName});
  $self->valdiff({name => $self->{cnatProtocolStatsName}},
      qw(cnatProtocolStatsInTranslate cnatProtocolStatsOutTranslate cnatProtocolStatsRejectCount));
  $self->{delta_cnatProtocolStatsTranslate} = 
      $self->{delta_cnatProtocolStatsInTranslate} +
      $self->{delta_cnatProtocolStatsOutTranslate};
  $self->{rejects} = $self->{delta_cnatProtocolStatsTranslate} ?
      (100 * $self->{delta_cnatProtocolStatsRejectCount} / 
      $self->{delta_cnatProtocolStatsTranslate}) : 0;
  $self->protect_value($self->{rejects}, 'rejects', 'percent');
}

sub check {
  my $self = shift;
  $self->add_info(sprintf '%.2f%% of all %s packets have been dropped/rejected',
      $self->{rejects}, $self->{cnatProtocolStatsName});
  $self->set_thresholds(warning => 30, critical => 50);
  $self->add_message($self->check_thresholds($self->{rejects}));
}

package Classes::Cisco::IOS::Component::BgpSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-BGP4-MIB', [
      ['prefixes', 'cbgpPeerAddrFamilyPrefixTable', 'Classes::Cisco::IOS::Component::BgpSubsystem::Prefix', sub { return $self->filter_name(shift->{cbgpPeerRemoteAddr}) } ],
  ]);
}


package Classes::Cisco::IOS::Component::BgpSubsystem::Prefix;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{cbgpPeerAddrFamilyAfi} = pop @{$self->{indices}};
  $self->{cbgpPeerAddrFamilySafi} = pop @{$self->{indices}};
  $self->{cbgpPeerRemoteAddr} = join(".", @{$self->{indices}});
}

sub check {
  my $self = shift;
  if ($self->mode =~ /prefix::count/) {
    $self->add_info(sprintf "peer %s accepted %d prefixes", 
        $self->{cbgpPeerRemoteAddr}, $self->{cbgpPeerAddrAcceptedPrefixes});
    $self->set_thresholds(metric => $self->{cbgpPeerRemoteAddr}.'_accepted_prefixes',
        warning => '1:', critical => '1:');
    $self->add_message($self->check_thresholds(
        metric => $self->{cbgpPeerRemoteAddr}.'_accepted_prefixes',
        value => $self->{cbgpPeerAddrAcceptedPrefixes}));
    $self->add_perfdata(
        label => $self->{cbgpPeerRemoteAddr}.'_accepted_prefixes',
        value => $self->{cbgpPeerAddrAcceptedPrefixes},
    );
  }
}
package Classes::Cisco::IOS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::IOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::IOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::IOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::hsrp/) {
    $self->analyze_and_check_hsrp_subsystem("Classes::HSRP::Component::HSRPSubsystem");
  } elsif ($self->mode =~ /device::users/) {
    $self->analyze_and_check_connection_subsystem("Classes::Cisco::IOS::Component::ConnectionSubsystem");
  } elsif ($self->mode =~ /device::config/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::ConfigSubsystem");
  } elsif ($self->mode =~ /device::interfaces::nat::sessions::count/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::NatSubsystem");
  } elsif ($self->mode =~ /device::interfaces::nat::rejects/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::NatSubsystem");
  } elsif ($self->mode =~ /device::bgp::prefix::count/) {
    $self->analyze_and_check_config_subsystem("Classes::Cisco::IOS::Component::BgpSubsystem");
  } else {
    $self->no_such_mode();
  }
}


package Classes::Cisco::NXOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

{
  our $cpmCPUTotalIndex = 0;
}

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-PROCESS-MIB', [
      ['cpus', 'cpmCPUTotalTable', 'Classes::Cisco::NXOS::Component::CpuSubsystem::Cpu' ],
  ]);
  if (scalar(@{$self->{cpus}}) == 0) {
    # maybe too old. i fake a cpu. be careful. this is a really bad hack
    my $response = $self->get_request(
        -varbindlist => [
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1},
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5},
            $Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{busyPer},
        ]
    );
    if (exists $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}}) {
      push(@{$self->{cpus}},
          Classes::Cisco::NXOS::Component::CpuSubsystem::Cpu->new(
              cpmCPUTotalPhysicalIndex => 0, #fake
              cpmCPUTotalIndex => 0, #fake
              cpmCPUTotal5sec => 0, #fake
              cpmCPUTotal5secRev => 0, #fake
              cpmCPUTotal1min => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}},
              cpmCPUTotal1minRev => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy1}},
              cpmCPUTotal5min => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5}},
              cpmCPUTotal5minRev => $response->{$Classes::Device::mibs_and_oids->{'OLD-CISCO-CPU-MIB'}->{avgBusy5}},
              cpmCPUMonInterval => 0, #fake
              cpmCPUTotalMonIntervalValue => 0, #fake
              cpmCPUInterruptMonIntervalValue => 0, #fake
      ));
    }
  }
}

package Classes::Cisco::NXOS::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{cpmCPUTotalIndex} = exists $self->{cpmCPUTotalIndex} ?
      $self->{cpmCPUTotalIndex} :
      $Classes::Cisco::NXOS::Component::CpuSubsystem::cpmCPUTotalIndex++;
  $self->{cpmCPUTotalPhysicalIndex} = exists $self->{cpmCPUTotalPhysicalIndex} ? 
      $self->{cpmCPUTotalPhysicalIndex} : 0;
  if (exists $self->{cpmCPUTotal5minRev}) {
    $self->{usage} = $self->{cpmCPUTotal5minRev};
  } else {
    $self->{usage} = $self->{cpmCPUTotal5min};
  }
  $self->protect_value($self->{cpmCPUTotalIndex}.$self->{cpmCPUTotalPhysicalIndex}, 'usage', 'percent');
  if ($self->{cpmCPUTotalPhysicalIndex}) {
    $self->{entPhysicalName} = $self->get_snmp_object('ENTITY-MIB', 'entPhysicalName', $self->{cpmCPUTotalPhysicalIndex});
    # This object is a user-assigned asset tracking identifier for the physical entity
    # as specified by a network manager, and provides non-volatile storage of this 
    # information. On the first instantiation of an physical entity, the value of
    # entPhysicalAssetID associated with that entity is set to the zero-length string.
    # ...
    # If write access is implemented for an instance of entPhysicalAssetID, and a value
    # is written into the instance, the agent must retain the supplied value in the
    # entPhysicalAssetID instance associated with the same physical entity for as long
    # as that entity remains instantiated. This includes instantiations across all 
    # re-initializations/reboots of the network management system, including those
    # which result in a change of the physical entity's entPhysicalIndex value.
    $self->{entPhysicalAssetID} = $self->get_snmp_object('ENTITY-MIB', 'entPhysicalAssetID', $self->{cpmCPUTotalPhysicalIndex});
    $self->{name} = $self->{entPhysicalName};
    $self->{name} .= ' '.$self->{entPhysicalAssetID} if $self->{entPhysicalAssetID};
    $self->{label} = $self->{entPhysicalName};
    $self->{label} .= ' '.$self->{entPhysicalAssetID} if $self->{entPhysicalAssetID};
  } else {
    $self->{name} = $self->{cpmCPUTotalIndex};
    $self->{label} = $self->{cpmCPUTotalIndex};
  }
  return $self;
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s usage (5 min avg.) is %.2f%%',
      $self->{name}, $self->{usage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{usage}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{label}.'_usage',
      value => $self->{usage},
      uom => '%',
  );
}


package Classes::Cisco::NXOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CISCO-SYSTEM-EXT-MIB', (qw(
      cseSysMemoryUtilization)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{cseSysMemoryUtilization}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{cseSysMemoryUtilization});
    $self->set_thresholds(warning => 80, critical => 90);
    $self->add_message($self->check_thresholds($self->{cseSysMemoryUtilization}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{cseSysMemoryUtilization},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}


package Classes::Cisco::NXOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{sensor_subsystem} =
      Classes::Cisco::CISCOENTITYSENSORMIB::Component::SensorSubsystem->new();
  if ($self->implements_mib('CISCO-ENTITY-FRU-CONTROL-MIB')) {
    $self->{fru_subsystem} = Classes::Cisco::CISCOENTITYFRUCONTROLMIB::Component::EnvironmentalSubsystem->new();
  }
}

sub check {
  my $self = shift;
  $self->{sensor_subsystem}->check();
  if (exists $self->{fru_subsystem}) {
    $self->{fru_subsystem}->check();
  }
  if (! $self->check_messages()) {
    $self->clear_ok();
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{sensor_subsystem}->dump();
  if (exists $self->{fru_subsystem}) {
    $self->{fru_subsystem}->dump();
  }
}

package Classes::Cisco::NXOS::Component::FexSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-ETHERNET-FABRIC-EXTENDER-MIB', [
    ['fexes', 'cefexConfigTable', 'Classes::Cisco::NXOS::Component::FexSubsystem::Fex'],
  ]);
  if (scalar (@{$self->{fexes}}) == 0) {
   # fallback
    $self->get_snmp_tables('ENTITY-MIB', [
      ['fexes', 'entPhysicalTable', 'Classes::Cisco::NXOS::Component::FexSubsystem::Fex'],
    ]);
    @{$self->{fexes}} = grep {
        $_->{entPhysicalClass} eq 'chassis' && $_->{entPhysicalDescr} =~ /fex/i; 
    } @{$self->{fexes}};
    if (scalar (@{$self->{fexes}}) == 0) {
      $self->get_snmp_tables('ENTITY-MIB', [
        ['fexes', 'entPhysicalTable', 'Classes::Cisco::NXOS::Component::FexSubsystem::Fex'],
      ]);
      # fallback
      my $known_fexes = {};
      @{$self->{fexes}} = grep {
        ! $known_fexes->{$_->{cefexConfigExtenderName}}++;
      } grep {
          $_->{entPhysicalClass} eq 'other' && $_->{entPhysicalDescr} =~ /fex.*cable/i; 
      } @{$self->{fexes}};
    }
  }
}

sub dump {
  my $self = shift;
  foreach (@{$self->{fexes}}) {
    $_->dump();
  }
}

sub check {
  my $self = shift;
  $self->add_info('counting fexes');
  $self->{numOfFexes} = scalar (@{$self->{fexes}});
  $self->{fexNameList} = [map { $_->{cefexConfigExtenderName} } @{$self->{fexes}}];
  if (scalar (@{$self->{fexes}}) == 0) {
    $self->add_unknown('no FEXes found');
  } else {
    # lookback, denn sonst muesste der check is_volatile sein und koennte bei
    # einem kurzen netzausfall fehler schmeissen.
    # empfehlung: check_interval 5 (muss jedesmal die entity-mib durchwalken)
    #             retry_interval 2
    #             max_check_attempts 2
    # --lookback 360
    $self->opts->override_opt('lookback', 1800) if ! $self->opts->lookback;
    $self->valdiff({name => $self->{name}, lastarray => 1},
        qw(fexNameList numOfFexes));
    if (scalar(@{$self->{delta_found_fexNameList}}) > 0) {
      $self->add_warning(sprintf '%d new FEX(es) (%s)',
          scalar(@{$self->{delta_found_fexNameList}}),
          join(", ", @{$self->{delta_found_fexNameList}}));
    }
    if (scalar(@{$self->{delta_lost_fexNameList}}) > 0) {
      $self->add_critical(sprintf '%d FEXes missing (%s)',
          scalar(@{$self->{delta_lost_fexNameList}}),
          join(", ", @{$self->{delta_lost_fexNameList}}));
    }
    $self->add_ok(sprintf 'found %d FEXes', scalar (@{$self->{fexes}}));
    $self->add_perfdata(
        label => 'num_fexes',
        value => $self->{numOfFexes},
    );
  }
}


package Classes::Cisco::NXOS::Component::FexSubsystem::Fex;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{original_cefexConfigExtenderName} = $self->{cefexConfigExtenderName};
  if (exists $self->{entPhysicalClass}) {
    # stammt aus ENTITY-MIB
    if ($self->{entPhysicalDescr} =~ /^FEX[^\d]*(\d+)/i) {
      $self->{cefexConfigExtenderName} = "FEX".$1;
    } else {
      $self->{cefexConfigExtenderName} = $self->{entPhysicalDescr};
    }
  } else {
    # stammt aus CISCO-ETHERNET-FABRIC-EXTENDER-MIB, kann FEX101-J8-VT04.01 heissen
    if ($self->{cefexConfigExtenderName} =~ /^FEX[^\d]*(\d+)/i) {
      $self->{cefexConfigExtenderName} = "FEX".$1;
    }
  }
}

package Classes::Cisco::NXOS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->mult_snmp_max_msg_size(10);
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::NXOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::cisco::fex::watch/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::NXOS::Component::FexSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::IOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::NXOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::hsrp/) {
    $self->analyze_and_check_hsrp_subsystem("Classes::HSRP::Component::HSRPSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco::WLC::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('AIRESPACE-SWITCHING-MIB', (qw(
      agentTotalMemory agentFreeMemory)));
  $self->{memory_usage} = $self->{agentFreeMemory} ? 
      ( ($self->{agentTotalMemory} - $self->{agentFreeMemory}) / $self->{agentTotalMemory} * 100) : 100;
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'memory usage is %.2f%%',
      $self->{memory_usage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{memory_usage}));
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{memory_usage},
      uom => '%',
  );
}

package Classes::Cisco::WLC::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $type = 0;
  $self->get_snmp_objects('AIRESPACE-SWITCHING-MIB', (qw(
      agentCurrentCPUUtilization)));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu usage is %.2f%%',
      $self->{agentCurrentCPUUtilization});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{agentCurrentCPUUtilization}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{agentCurrentCPUUtilization},
      uom => '%',
  );
}

package Classes::Cisco::WLC::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{ps1_present} = $self->get_snmp_object(
      'AIRESPACE-SWITCHING-MIB', 'agentSwitchInfoPowerSupply1Present', 0);
  $self->{ps1_operational} = $self->get_snmp_object(
      'AIRESPACE-SWITCHING-MIB', 'agentSwitchInfoPowerSupply1Operational', 0);
  $self->{ps2_present} = $self->get_snmp_object(
      'AIRESPACE-SWITCHING-MIB', 'agentSwitchInfoPowerSupply2Present', 0);
  $self->{ps2_operational} = $self->get_snmp_object(
      'AIRESPACE-SWITCHING-MIB', 'agentSwitchInfoPowerSupply2Operational', 0);
  $self->{temp_environment} = $self->get_snmp_object(
      'AIRESPACE-WIRELESS-MIB', 'bsnOperatingTemperatureEnvironment', 0);
  $self->{temp_value} = $self->get_snmp_object(
      'AIRESPACE-WIRELESS-MIB', 'bsnSensorTemperature', 0);
  $self->{temp_alarm_low} = $self->get_snmp_object(
      'AIRESPACE-WIRELESS-MIB', 'bsnTemperatureAlarmLowLimit', 0);
  $self->{temp_alarm_high} = $self->get_snmp_object(
      'AIRESPACE-WIRELESS-MIB', 'bsnTemperatureAlarmHighLimit', 0);
}

sub check {
  my $self = shift;
  #$self->blacklist('t', $self->{cpmCPUTotalPhysicalIndex});
  my $tinfo = sprintf 'temperature is %.2fC (%s env %s-%s)',
      $self->{temp_value}, $self->{temp_environment},
      $self->{temp_alarm_low}, $self->{temp_alarm_high};
  $self->set_thresholds(
      warning => $self->{temp_alarm_low}.':'.$self->{temp_alarm_high},
      critical => $self->{temp_alarm_low}.':'.$self->{temp_alarm_high});
  $self->add_message($self->check_thresholds($self->{temp_value}), $tinfo);
  $self->add_perfdata(
      label => 'temperature',
      value => $self->{temp_value},
  );
  if ($self->{ps1_present} eq "true") {
    if ($self->{ps1_operational} ne "true") {
      $self->add_warning("Powersupply 1 is not operational");
    }
  }
  if ($self->{ps2_present} eq "true") {
    if ($self->{ps2_operational} ne "true") {
      $self->add_warning("Powersupply 2 is not operational");
    }
  }
  my $p1info = sprintf "PS1 is %spresent and %soperational",
      $self->{ps1_present} eq "true" ? "" : "not ",
      $self->{ps1_operational} eq "true" ? "" : "not ";
  my $p2info = sprintf "PS2 is %spresent and %soperational",
      $self->{ps2_present} eq "true" ? "" : "not ",
      $self->{ps2_operational} eq "true" ? "" : "not ";
  $self->add_info($tinfo.", ".$p1info.", ".$p2info);
}

sub dump {
  my $self = shift;
  printf "[TEMPERATURE]\n";
  foreach (qw(temp_environment temp_value temp_alarm_low temp_alarm_high)) {
    if (exists $self->{$_}) {
      printf "%s: %s\n", $_, $self->{$_};
    }
  }
  printf "[PS1]\n";
  foreach (qw(ps1_present ps1_operational)) {
    if (exists $self->{$_}) {
      printf "%s: %s\n", $_, $self->{$_};
    }
  }
  printf "[PS2]\n";
  foreach (qw(ps2_present ps2_operational)) {
    if (exists $self->{$_}) {
      printf "%s: %s\n", $_, $self->{$_};
    }
  }
  printf "info: %s\n", $self->{info};
  printf "\n";
}

package Classes::Cisco::WLC::Component::WlanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{name} = $self->get_snmp_object('MIB-II', 'sysName', 0);
  $self->get_snmp_tables('AIRESPACE-WIRELESS-MIB', [
      ['aps', 'bsnAPTable', 'Classes::Cisco::WLC::Component::WlanSubsystem::AP', sub { return $self->filter_name(shift->{bsnAPName}) } ],
      ['ifs', 'bsnAPIfTable', 'Classes::Cisco::WLC::Component::WlanSubsystem::AP' ],
      ['ifloads', 'bsnAPIfLoadParametersTable', 'Classes::Cisco::WLC::Component::WlanSubsystem::IFLoad' ],
  ]);
  $self->assign_loads_to_ifs();
  $self->assign_ifs_to_aps();
}

sub check {
  my $self = shift;
  $self->add_info('checking access points');
  $self->{numOfAPs} = scalar (@{$self->{aps}});
  $self->{apNameList} = [map { $_->{bsnAPName} } @{$self->{aps}}];
  if (scalar (@{$self->{aps}}) == 0) {
    $self->add_unknown('no access points found');
  } else {
    foreach (@{$self->{aps}}) {
      $_->check();
    }
    if ($self->mode =~ /device::wlan::aps::watch/) {
      $self->opts->override_opt('lookback', 1800) if ! $self->opts->lookback;
      $self->valdiff({name => $self->{name}, lastarray => 1},
          qw(apNameList numOfAPs));
      if (scalar(@{$self->{delta_found_apNameList}}) > 0) {
      #if (scalar(@{$self->{delta_found_apNameList}}) > 0 &&
      #    $self->{delta_timestamp} > $self->opts->lookback) {
        $self->add_warning(sprintf '%d new access points (%s)',
            scalar(@{$self->{delta_found_apNameList}}),
            join(", ", @{$self->{delta_found_apNameList}}));
      }
      if (scalar(@{$self->{delta_lost_apNameList}}) > 0) {
        $self->add_critical(sprintf '%d access points missing (%s)',
            scalar(@{$self->{delta_lost_apNameList}}),
            join(", ", @{$self->{delta_lost_apNameList}}));
      }
      $self->add_ok(sprintf 'found %d access points', scalar (@{$self->{aps}}));
      $self->add_perfdata(
          label => 'num_aps',
          value => scalar (@{$self->{aps}}),
      );
    } elsif ($self->mode =~ /device::wlan::aps::count/) {
      $self->set_thresholds(warning => '10:', critical => '5:');
      $self->add_message($self->check_thresholds(
          scalar (@{$self->{aps}})), 
          sprintf 'found %d access points', scalar (@{$self->{aps}}));
      $self->add_perfdata(
          label => 'num_aps',
          value => scalar (@{$self->{aps}}),
      );
    } elsif ($self->mode =~ /device::wlan::aps::status/) {
      if ($self->opts->report eq "short") {
        $self->clear_ok();
        $self->add_ok('no problems') if ! $self->check_messages();
      }
    } elsif ($self->mode =~ /device::wlan::aps::list/) {
      foreach (@{$self->{aps}}) {
        printf "%s\n", $_->{bsnAPName};
      }
    }
  }
}

sub assign_ifs_to_aps {
  my $self = shift;
  foreach my $ap (@{$self->{aps}}) {
    $ap->{interfaces} = [];
    foreach my $if (@{$self->{ifs}}) {
      if ($if->{flat_indices} eq $ap->{bsnAPDot3MacAddress}.".".$if->{bsnAPIfSlotId}) {
        push(@{$ap->{interfaces}}, $if);
      }
    }
    $ap->{NumOfClients} = 0;
    map {$ap->{NumOfClients} += $_->{bsnAPIfLoadNumOfClients} }
        @{$ap->{interfaces}};
  }
}

sub assign_loads_to_ifs {
  my $self = shift;
  foreach my $if (@{$self->{ifs}}) {
    foreach my $load (@{$self->{ifloads}}) {
      if ($load->{flat_indices} eq $if->{flat_indices}) {
        map { $if->{$_} = $load->{$_} } grep { $_ !~ /indices/ } keys %{$load};
      }
    }
  }
}


package Classes::Cisco::WLC::Component::WlanSubsystem::IF;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;


package Classes::Cisco::WLC::Component::WlanSubsystem::IFLoad;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;


package Classes::Cisco::WLC::Component::WlanSubsystem::AP;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  if ($self->{bsnAPDot3MacAddress} && $self->{bsnAPDot3MacAddress} =~ /0x(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})/) {
    $self->{bsnAPDot3MacAddress} = join(".", map { hex($_) } ($1, $2, $3, $4, $5, $6));
  } elsif ($self->{bsnAPDot3MacAddress} && unpack("H12", $self->{bsnAPDot3MacAddress}) =~ /(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})(\w{2})/) {
    $self->{bsnAPDot3MacAddress} = join(".", map { hex($_) } ($1, $2, $3, $4, $5, $6));
  }
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'access point %s is %s (%d interfaces with %d clients)',
      $self->{bsnAPName}, $self->{bsnAPOperationStatus},
      scalar(@{$self->{interfaces}}), $self->{NumOfClients});
  if ($self->mode =~ /device::wlan::aps::status/) {
    if ($self->{bsnAPOperationStatus} eq 'disassociating') {
      $self->add_critical();
    } elsif ($self->{bsnAPOperationStatus} eq 'downloading') {
      # das verschwindet hoffentlich noch vor dem HARD-state
      $self->add_warning();
    } elsif ($self->{bsnAPOperationStatus} eq 'associated') {
      $self->add_ok();
    } else {
      $self->add_unknown();
    }
  }
}

package Classes::Cisco::WLC;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::WLC::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::WLC::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::WLC::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::wlan/) {
    $self->analyze_and_check_wlan_subsystem("Classes::Cisco::WLC::Component::WlanSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco::PrimeNCS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::HOSTRESOURCESMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::HOSTRESOURCESMIB::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco::UCOS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::HOSTRESOURCESMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::HOSTRESOURCESMIB::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::phone::cm/) {
    $self->analyze_and_check_cm_subsystem("Classes::Cisco::CCM::Component::CmSubsystem");
  } elsif ($self->mode =~ /device::phone/) {
    $self->analyze_and_check_phone_subsystem("Classes::Cisco::CCM::Component::PhoneSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco::CCM::Component::PhoneSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CISCO-CCM-MIB', (qw(
      ccmRegisteredPhones ccmUnregisteredPhones ccmRejectedPhones)));
  if (! defined $self->{ccmRegisteredPhones}) {
    $self->get_snmp_tables('CISCO-CCM-MIB', [
        ['ccms', 'ccmTable', 'Classes::Cisco::CCM::Component::CmSubsystem::Cm'],
    ]);
  }
}

sub check {
  my $self = shift;
  if (! defined $self->{ccmRegisteredPhones}) {
    foreach (qw(ccmRegisteredPhones ccmUnregisteredPhones ccmRejectedPhones)) {
      $self->{$_} = 0;
    }
    if (! scalar(@{$self->{ccms}})) {
      $self->add_ok('cm is down');
    } else {
      $self->add_unknown('unable to count phones');
    }
  }
  $self->add_info(sprintf 'phones: %d registered, %d unregistered, %d rejected',
      $self->{ccmRegisteredPhones},
      $self->{ccmUnregisteredPhones},
      $self->{ccmRejectedPhones});
  $self->set_thresholds(warning => 10, critical => 20);
  $self->add_message($self->check_thresholds($self->{ccmRejectedPhones}));
  $self->add_perfdata(
      label => 'registered',
      value => $self->{ccmRegisteredPhones},
  );
  $self->add_perfdata(
      label => 'unregistered',
      value => $self->{ccmUnregisteredPhones},
  );
  $self->add_perfdata(
      label => 'rejected',
      value => $self->{ccmRejectedPhones},
  );
}

package Classes::Cisco::CCM::Component::CmSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CISCO-CCM-MIB', [
      ['ccms', 'ccmTable', 'Classes::Cisco::CCM::Component::CmSubsystem::Cm'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{ccms}}) {
    $_->check();
  }
  if (! scalar(@{$self->{ccms}})) {
    $self->add_message(
        defined $self->opts->mitigation() ? $self->opts->mitigation() : 2,
        'local callmanager is down');
  }
}


package Classes::Cisco::CCM::Component::CmSubsystem::Cm;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cm %s is %s',
      $self->{ccmName},
      $self->{ccmStatus});
  $self->add_message($self->{ccmStatus} eq 'up' ? OK : CRITICAL);
}

package Classes::Cisco::CCM;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::HOSTRESOURCESMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::HOSTRESOURCESMIB::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::phone::cm/) {
    $self->analyze_and_check_cm_subsystem("Classes::Cisco::CCM::Component::CmSubsystem");
  } elsif ($self->mode =~ /device::phone/) {
    $self->analyze_and_check_phone_subsystem("Classes::Cisco::CCM::Component::PhoneSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco::AsyncOS::Component::KeySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ASYNCOS-MAIL-MIB', [
      ['keys', 'keyExpirationTable', 'Classes::Cisco::AsyncOS::Component::KeySubsystem::Key'],
  ]);
}

package Classes::Cisco::AsyncOS::Component::KeySubsystem::Key;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{keyDaysUntilExpire} = int($self->{keySecondsUntilExpire} / 86400);
  if ($self->{keyIsPerpetual} eq 'true') {
    $self->add_info(sprintf 'perpetual key %d (%s) never expires',
        $self->{keyExpirationIndex},
        $self->{keyDescription});
    $self->add_ok();
  } else {
    $self->add_info(sprintf 'key %d (%s) expires in %d days',
        $self->{keyExpirationIndex},
        $self->{keyDescription},
        $self->{keyDaysUntilExpire});
    $self->set_thresholds(warning => '14:', critical => '7:');
    $self->add_message($self->check_thresholds($self->{keyDaysUntilExpire}));
  }
  $self->add_perfdata(
      label => sprintf('lifetime_%s', $self->{keyDaysUntilExpire}),
      value => $self->{keyDaysUntilExpire},
      thresholds => $self->{keyIsPerpetual} eq 'true' ? 0 : 1,
  );
}

package Classes::Cisco::AsyncOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('ASYNCOS-MAIL-MIB', (qw(
      perCentMemoryUtilization memoryAvailabilityStatus)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'memory usage is %.2f%% (%s)',
      $self->{perCentMemoryUtilization}, $self->{memoryAvailabilityStatus});
  $self->set_thresholds(warning => 80, critical => 90);
  if ($self->check_thresholds($self->{perCentMemoryUtilization})) {
    $self->add_message($self->check_thresholds($self->{perCentMemoryUtilization}));
  } elsif ($self->{memoryAvailabilityStatus} eq 'memoryShortage') {
    $self->add_warning();
    $self->set_thresholds(warning => $self->{perCentMemoryUtilization}, critical => 90);
  } elsif ($self->{memoryAvailabilityStatus} eq 'memoryFull') {
    $self->add_critical();
    $self->set_thresholds(warning => 80, critical => $self->{perCentMemoryUtilization});
  } else {
    $self->add_ok();
  }
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{perCentMemoryUtilization},
      uom => '%',
  );
}

package Classes::Cisco::AsyncOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('ASYNCOS-MAIL-MIB', (qw(
      perCentCPUUtilization)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%',
      $self->{perCentCPUUtilization});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{perCentCPUUtilization}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{perCentCPUUtilization},
      uom => '%',
  );
}

package Classes::Cisco::AsyncOS::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ASYNCOS-MAIL-MIB', [
      ['temperatures', 'temperatureTable', 'Classes::Cisco::AsyncOS::Component::TemperatureSubsystem::Temperature'],
  ]);
}

package Classes::Cisco::AsyncOS::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->set_thresholds(warning => 60, critical => 70);
  $self->add_info(sprintf 'temperature %d (%s) is %s degree C',
        $self->{temperatureIndex},
        $self->{temperatureName},
        $self->{degreesCelsius});
  if ($self->check_thresholds($self->{degreesCelsius})) {
    $self->add_message($self->check_thresholds($self->{degreesCelsius}),
        $self->{info});
  }
  $self->add_perfdata(
      label => sprintf('temp_%s', $self->{temperatureIndex}),
      value => $self->{degreesCelsius},
  );
}

package Classes::Cisco::AsyncOS::Component::PowersupplySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ASYNCOS-MAIL-MIB', [
      ['supplies', 'powerSupplyTable', 'Classes::Cisco::AsyncOS::Component::PowersupplySubsystem::Powersupply'],
  ]);
}

package Classes::Cisco::AsyncOS::Component::PowersupplySubsystem::Powersupply;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'powersupply %d (%s) has status %s',
      $self->{powerSupplyIndex},
      $self->{powerSupplyName},
      $self->{powerSupplyStatus});
  if ($self->{powerSupplyStatus} eq 'powerSupplyNotInstalled') {
  } elsif ($self->{powerSupplyStatus} ne 'powerSupplyHealthy') {
    $self->add_critical();
  }
}

package Classes::Cisco::AsyncOS::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ASYNCOS-MAIL-MIB', [
      ['fans', 'fanTable', 'Classes::Cisco::AsyncOS::Component::FanSubsystem::Fan'],
  ]);
}

package Classes::Cisco::AsyncOS::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'fan %d (%s) has %s rpm',
      $self->{fanIndex},
      $self->{fanName},
      $self->{fanRPMs});
  $self->add_perfdata(
      label => sprintf('fan_c%s', $self->{fanIndex}),
      value => $self->{fanRPMs},
      thresholds => 0,
  );
}

package Classes::Cisco::AsyncOS::Component::RaidSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('ASYNCOS-MAIL-MIB', (qw(
      raidEvents)));
  $self->get_snmp_tables('ASYNCOS-MAIL-MIB', [
      ['raids', 'raidTable', 'Classes::Cisco::AsyncOS::Component::RaidSubsystem::Raid'],
  ]);
}

package Classes::Cisco::AsyncOS::Component::RaidSubsystem::Raid;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'raid %d has status %s',
      $self->{raidIndex},
      $self->{raidStatus});
  if ($self->{raidStatus} eq 'driveHealthy') {
  } elsif ($self->{raidStatus} eq 'driveRebuild') {
    $self->add_warning();
  } elsif ($self->{raidStatus} eq 'driveFailure') {
    $self->add_critical();
  }
}

package Classes::Cisco::AsyncOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  #
  # 1.3.6.1.4.1.9.9.13.1.1.0 ciscoEnvMonPresent (irgendein typ of envmon)
  # 
  $self->{fan_subsystem} =
      Classes::Cisco::AsyncOS::Component::FanSubsystem->new();
  $self->{temperature_subsystem} =
      Classes::Cisco::AsyncOS::Component::TemperatureSubsystem->new();
  $self->{powersupply_subsystem} = 
      Classes::Cisco::AsyncOS::Component::PowersupplySubsystem->new();
  $self->{raid_subsystem} = 
      Classes::Cisco::AsyncOS::Component::RaidSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{fan_subsystem}->check();
  $self->{temperature_subsystem}->check();
  $self->{powersupply_subsystem}->check();
  $self->{raid_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{fan_subsystem}->dump();
  $self->{temperature_subsystem}->dump();
  $self->{powersupply_subsystem}->dump();
  $self->{raid_subsystem}->dump();
}

package Classes::Cisco::AsyncOS;
our @ISA = qw(Classes::Cisco);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Cisco::AsyncOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Cisco::AsyncOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Cisco::AsyncOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::licenses::/) {
    $self->analyze_and_check_key_subsystem("Classes::Cisco::AsyncOS::Component::KeySubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Cisco;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
  '1.3.6.1.2.1',        # mib-2
  '1.3.6.1.4.1.9',      # cisco
  '1.3.6.1.4.1.9.1',      # ciscoProducts
  '1.3.6.1.4.1.9.2',      # local
  '1.3.6.1.4.1.9.3',      # temporary
  '1.3.6.1.4.1.9.4',      # pakmon
  '1.3.6.1.4.1.9.5',      # workgroup
  '1.3.6.1.4.1.9.6',      # otherEnterprises
  '1.3.6.1.4.1.9.7',      # ciscoAgentCapability
  '1.3.6.1.4.1.9.8',      # ciscoConfig
  '1.3.6.1.4.1.9.9',      # ciscoMgmt
  '1.3.6.1.4.1.9.10',      # ciscoExperiment
  '1.3.6.1.4.1.9.11',      # ciscoAdmin
  '1.3.6.1.4.1.9.12',      # ciscoModules
  '1.3.6.1.4.1.9.13',      # lightstream
  '1.3.6.1.4.1.9.14',      # ciscoworks
  '1.3.6.1.4.1.9.15',      # newport
  '1.3.6.1.4.1.9.16',      # ciscoPartnerProducts
  '1.3.6.1.4.1.9.17',      # ciscoPolicy
  '1.3.6.1.4.1.9.18',      # ciscoPolicyAuto
  '1.3.6.1.4.1.9.19',      # ciscoDomains
  '1.3.6.1.4.1.14179.1',   # airespace-switching-mib
  '1.3.6.1.4.1.14179.2',   # airespace-wireless-mib
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /Cisco NX-OS/i) {
    bless $self, 'Classes::Cisco::NXOS';
    $self->debug('using Classes::Cisco::NXOS');
  } elsif ($self->{productname} =~ /Cisco Controller/i) {
    bless $self, 'Classes::Cisco::WLC';
    $self->debug('using Classes::Cisco::WLC');
  } elsif ($self->{productname} =~ /Cisco.*(IronPort|AsyncOS)/i) {
    bless $self, 'Classes::Cisco::AsyncOS';
    $self->debug('using Classes::Cisco::AsyncOS');
  } elsif ($self->{productname} =~ /Cisco.*Prime Network Control System/i) {
    bless $self, 'Classes::Cisco::PrimeNCS';
    $self->debug('using Classes::Cisco::PrimeNCS');
  } elsif ($self->{productname} =~ /UCOS /i) {
    bless $self, 'Classes::Cisco::UCOS';
    $self->debug('using Classes::Cisco::UCOS');
  } elsif ($self->{productname} =~ /Cisco (PIX|Adaptive) Security Appliance/i) {
    bless $self, 'Classes::Cisco::ASA';
    $self->debug('using Classes::Cisco::ASA');
  } elsif ($self->{productname} =~ /Cisco/i) {
    bless $self, 'Classes::Cisco::IOS';
    $self->debug('using Classes::Cisco::IOS');
  } elsif ($self->{productname} =~ /Fujitsu Intelligent Blade Panel 30\/12/i) {
    bless $self, 'Classes::Cisco::IOS';
    $self->debug('using Classes::Cisco::IOS');
  } elsif ($self->get_snmp_object('MIB-II', 'sysObjectID', 0) eq '1.3.6.1.4.1.9.1.1348') {
    bless $self, 'Classes::Cisco::CCM';
    $self->debug('using Classes::Cisco::CCM');
  } elsif ($self->get_snmp_object('MIB-II', 'sysObjectID', 0) eq '1.3.6.1.4.1.9.1.746') {
    bless $self, 'Classes::Cisco::CCM';
    $self->debug('using Classes::Cisco::CCM');
  }
  if (ref($self) ne "Classes::Cisco") {
    $self->init();
  }
}

package Classes::Nortel::S5;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Nortel::S5::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Nortel::S5::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Nortel::S5::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Nortel;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->implements_mib('S5-CHASSIS-MIB')) {
    bless $self, 'Classes::Nortel::S5';
    $self->debug('using Classes::Nortel::S5');
  }
  if (ref($self) ne "Classes::Nortel") {
    $self->init();
  }
}

package Classes::Juniper::NetScreen::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('NETSCREEN-RESOURCE-MIB', (qw(
      nsResCpuAvg)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{nsResCpuAvg});
  $self->set_thresholds(warning => 50, critical => 90);
  $self->add_message($self->check_thresholds($self->{nsResCpuAvg}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{nsResCpuAvg},
      uom => '%',
  );
}


package Classes::Juniper::NetScreen::Component::CpuSubsystem::Load;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s is %.2f', lc $self->{laNames}, $self->{laLoadFloat});
  $self->set_thresholds(warning => $self->{laConfig},
      critical => $self->{laConfig});
  $self->add_message($self->check_thresholds($self->{laLoadFloat}));
  $self->add_perfdata(
      label => lc $self->{laNames},
      value => $self->{laLoadFloat},
  );
}

package Classes::Juniper::NetScreen::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('NETSCREEN-RESOURCE-MIB', (qw(
      nsResMemAllocate nsResMemLeft nsResMemFrag)));
  my $mem_total = $self->{nsResMemAllocate} + $self->{nsResMemLeft};
  $self->{mem_usage} = $self->{nsResMemAllocate} / $mem_total * 100;
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{mem_usage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%', $self->{mem_usage});
    $self->set_thresholds(warning => 80,
        critical => 90);
    $self->add_message($self->check_thresholds($self->{mem_usage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{mem_usage},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

package Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects("NETSCREEN-CHASSIS-MIB", (qw(
      sysBatteryStatus)));
  $self->get_snmp_tables("NETSCREEN-CHASSIS-MIB", [
      ['fans', 'nsFanTable', 'Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Fan'],
      ['power', 'nsPowerTable', 'Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Power'],
      ['slots', 'nsSlotTable', 'Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Slot'],
      ['temperatures', 'nsTemperatureTable', 'Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Temperature'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{fans}}, @{$self->{power}}, @{$self->{slots}}, @{$self->{temperatures}}) {
    $_->check();
  }
}


package Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "fan %s (%s) is %s",
      $self->{nsFanId}, $self->{nsFanDesc}, $self->{nsFanStatus});
  if ($self->{nsFanStatus} eq "notInstalled") {
  } elsif ($self->{nsFanStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsFanStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Power;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "power supply %s (%s) is %s",
      $self->{nsPowerId}, $self->{nsPowerDesc}, $self->{nsPowerStatus});
  if ($self->{nsPowerStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsPowerStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Slot;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "%s slot %s (%s) is %s",
      $self->{nsSlotType}, $self->{nsSlotId}, $self->{nsSlotSN}, $self->{nsSlotStatus});
  if ($self->{nsSlotStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsSlotStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "temperature %s is %sC",
      $self->{nsTemperatureId}, $self->{nsTemperatureDesc}, $self->{nsTemperatureCur});
  $self->add_ok();
  $self->add_perfdata(
      label => 'temp_'.$self->{nsTemperatureId},
      value => $self->{nsTemperatureCur},
  );
}

package Classes::Juniper::NetScreen;
our @ISA = qw(Classes::Juniper);
use strict;

use constant trees => (
  '1.3.6.1.2.1',        # mib-2
  '1.3.6.1.2.1.105',
);

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Juniper::NetScreen::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Juniper::NetScreen::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Juniper::NetScreen::Component::EnvironmentalSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Juniper::IVE::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('JUNIPER-IVE-MIB', (qw(
      iveMemoryUtil iveSwapUtil)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'memory usage is %.2f%%, swap usage is %.2f%%',
      $self->{iveMemoryUtil}, $self->{iveSwapUtil});
  $self->set_thresholds(warning => 90, critical => 95);
  $self->add_message($self->check_thresholds($self->{iveMemoryUtil}),
      sprintf 'memory usage is %.2f%%', $self->{iveMemoryUtil});
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{iveMemoryUtil},
      uom => '%',
  );
  $self->set_thresholds(warning => 5, critical => 10);
  $self->add_message($self->check_thresholds($self->{iveSwapUtil}),
      sprintf 'swap usage is %.2f%%', $self->{iveSwapUtil});
  $self->add_perfdata(
      label => 'swap_usage',
      value => $self->{iveSwapUtil},
      uom => '%',
  );
}

package Classes::Juniper::IVE::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('JUNIPER-IVE-MIB', (qw(
      iveCpuUtil)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{iveCpuUtil});
  # http://www.juniper.net/techpubs/software/ive/guides/howtos/SA-IC-MAG-SNMP-Monitoring-Guide.pdf
  $self->set_thresholds(warning => 50, critical => 90);
  $self->add_message($self->check_thresholds($self->{iveCpuUtil}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{iveCpuUtil},
      uom => '%',
  );
}

sub unix_init {
  my $self = shift;
  my %params = @_;
  my $type = 0;
  $self->get_snmp_tables('UCD-SNMP-MIB', [
      ['loads', 'laTable', 'Classes::Juniper::IVE::Component::CpuSubsystem::Load'],
  ]);
}

sub unix_check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking loads');
  foreach (@{$self->{loads}}) {
    $_->check();
  }
}

sub unix_dump {
  my $self = shift;
  foreach (@{$self->{loads}}) {
    $_->dump();
  }
}


package Classes::Juniper::IVE::Component::CpuSubsystem::Load;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s is %.2f', lc $self->{laNames}, $self->{laLoadFloat});
  $self->set_thresholds(warning => $self->{laConfig},
      critical => $self->{laConfig});
  $self->add_message($self->check_thresholds($self->{laLoadFloat}));
  $self->add_perfdata(
      label => lc $self->{laNames},
      value => $self->{laLoadFloat},
  );
}

package Classes::Juniper::IVE::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{disk_subsystem} =
      Classes::Juniper::IVE::Component::DiskSubsystem->new();
  $self->get_snmp_objects('JUNIPER-IVE-MIB', (qw(
      iveTemperature fanDescription psDescription raidDescription)));
}

sub check {
  my $self = shift;
  $self->{disk_subsystem}->check();
  $self->add_info(sprintf "temperature is %.2f deg", $self->{iveTemperature});
  $self->set_thresholds(warning => 70, critical => 75);
  $self->check_thresholds(0);
  $self->add_perfdata(
      label => 'temperature',
      value => $self->{iveTemperature},
      warning => $self->{warning},
      critical => $self->{critical},
  );
  if ($self->{fanDescription} && $self->{fanDescription} =~ /(failed)|(threshold)/) {
    $self->add_critical($self->{fanDescription});
  }
  if ($self->{psDescription} && $self->{psDescription} =~ /failed/) {
    $self->add_critical($self->{psDescription});
  }
  if ($self->{raidDescription} && $self->{raidDescription} =~ /(failed)|(unknown)/) {
    $self->add_critical($self->{raidDescription});
  }
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{disk_subsystem}->dump();
}

package Classes::Juniper::IVE::Component::DiskSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('JUNIPER-IVE-MIB', (qw(
      diskFullPercent)));
}

sub check {
  my $self = shift;
  $self->add_info('checking disks');
  $self->add_info(sprintf 'disk is %.2f%% full',
      $self->{diskFullPercent});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{diskFullPercent}));
  $self->add_perfdata(
      label => 'disk_usage',
      value => $self->{diskFullPercent},
      uom => '%',
  );
}

package Classes::Juniper::IVE::Component::UserSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('JUNIPER-IVE-MIB', (qw(
      iveSSLConnections iveVPNTunnels 
      signedInWebUsers signedInMailUsers meetingUserCount
      iveConcurrentUsers clusterConcurrentUsers)));
  foreach (qw(
      iveSSLConnections iveVPNTunnels 
      signedInWebUsers signedInMailUsers meetingUserCount
      iveConcurrentUsers clusterConcurrentUsers)) {
    $self->{$_} = 0 if ! defined $self->{$_};
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'Users: sslconns=%d cluster=%d, node=%d, web=%d, mail=%d, meeting=%d',
      $self->{iveSSLConnections},
      $self->{clusterConcurrentUsers},
      $self->{iveConcurrentUsers},
      $self->{signedInWebUsers},
      $self->{signedInMailUsers},
      $self->{meetingUserCount});
  $self->add_ok();
  $self->add_perfdata(
      label => 'sslconns',
      value => $self->{iveSSLConnections},
  );
  $self->add_perfdata(
      label => 'web_users',
      value => $self->{signedInWebUsers},
  );
  $self->add_perfdata(
      label => 'mail_users',
      value => $self->{signedInMailUsers},
  );
  $self->add_perfdata(
      label => 'meeting_users',
      value => $self->{meetingUserCount},
  );
  $self->add_perfdata(
      label => 'concurrent_users',
      value => $self->{iveConcurrentUsers},
  );
  $self->add_perfdata(
      label => 'cluster_concurrent_users',
      value => $self->{clusterConcurrentUsers},
  );
}
package Classes::Juniper::IVE;
our @ISA = qw(Classes::Juniper);
use strict;

use constant trees => (
  '1.3.6.1.2.1',        # mib-2
  '1.3.6.1.2.1.105',
);

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Juniper::IVE::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Juniper::IVE::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Juniper::IVE::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::users/) {
    $self->analyze_and_check_user_subsystem("Classes::Juniper::IVE::Component::UserSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Juniper;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
    '1.3.6.1.4.1.4874.',
    '1.3.6.1.4.1.3224.',
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /NetScreen/i) {
    bless $self, 'Classes::Juniper::NetScreen';
    $self->debug('using Classes::Juniper::NetScreen');
  } elsif ($self->{productname} =~ /Juniper.*MAG\-\d+/i) {
    # Juniper Networks,Inc,MAG-4610,7.2R10
    bless $self, 'Classes::Juniper::IVE';
    $self->debug('using Classes::Juniper::IVE');
  }
  if (ref($self) ne "Classes::Juniper") {
    $self->init();
  }
}

package Classes::AlliedTelesyn;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  $self->no_such_mode();
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::AlliedTelesyn::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::AlliedTelesyn::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::AlliedTelesyn::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::hsrp/) {
    $self->analyze_and_check_hsrp_subsystem("Classes::HSRP::Component::HSRPSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Fortigate::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('FORTINET-FORTIGATE-MIB', (qw(
      fgSysMemUsage)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{fgSysMemUsage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{fgSysMemUsage});
    $self->set_thresholds(warning => 80, critical => 90);
    $self->add_message($self->check_thresholds($self->{fgSysMemUsage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{fgSysMemUsage},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

package Classes::Fortigate::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my %params = @_;
  my $type = 0;
  $self->get_snmp_objects('FORTINET-FORTIGATE-MIB', (qw(
      fgSysCpuUsage)));
}

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{fgSysCpuUsage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{fgSysCpuUsage}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{fgSysCpuUsage},
      uom => '%',
  );
}

package Classes::Fortigate::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{sensor_subsystem} =
      Classes::Fortigate::Component::SensorSubsystem->new();
  $self->{disk_subsystem} =
      Classes::Fortigate::Component::DiskSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{sensor_subsystem}->check();
  $self->{disk_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{sensor_subsystem}->dump();
  $self->{disk_subsystem}->dump();
}

package Classes::Fortigate::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FORTINET-FORTIGATE-MIB', [
      ['sensors', 'fgHwSensorTable', 'Classes::Fortigate::Component::SensorSubsystem::Sensor'],
  ]);
}

package Classes::Fortigate::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'sensor %s alarm status is %s',
      $self->{fgHwSensorEntName},
      $self->{fgHwSensorEntValueStatus});
  if ($self->{fgHwSensorEntValueStatus} && $self->{fgHwSensorEntValueStatus} eq "true") {
    $self->add_critical();
  }
  if ($self->{fgHwSensorEntValue}) {
    $self->add_perfdata(
        label => sprintf('sensor_%s', $self->{fgHwSensorEntName}),
        value => $self->{swSensorValue},
    );
  }
}

package Classes::Fortigate;
our @ISA = qw(Classes::Brocade);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Fortigate::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Fortigate::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Fortigate::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::FabOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  foreach (qw(swMemUsage swMemUsageLimit1 swMemUsageLimit3 swMemPollingInterval
      swMemNoOfRetries swMemAction)) {
    $self->{$_} = $self->valid_response('SW-MIB', $_, 0);
  }
  $self->get_snmp_objects('SW-MIB', (qw(
      swFwFabricWatchLicense)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{swMemUsage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{swMemUsage});
    $self->set_thresholds(warning => $self->{swMemUsageLimit1},
        critical => $self->{swMemUsageLimit3});
    $self->add_message($self->check_thresholds($self->{swMemUsage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{swMemUsage},
        uom => '%',
    );
  } elsif ($self->{swFwFabricWatchLicense} eq 'swFwNotLicensed') {
    $self->add_unknown('please install a fabric watch license');
  } else {
    my $swFirmwareVersion = $self->get_snmp_object('SW-MIB', 'swFirmwareVersion');
    if ($swFirmwareVersion && $swFirmwareVersion =~ /^v6/) {
      $self->add_ok('memory usage is not implemented');
    } else {
      $self->add_unknown('cannot aquire memory usage');
    }
  }
}

package Classes::FabOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  foreach (qw(swCpuUsage swCpuNoOfRetries swCpuUsageLimit swCpuPollingInterval
      swCpuAction)) {
    $self->{$_} = $self->valid_response('SW-MIB', $_, 0);
  }
  $self->get_snmp_objects('SW-MIB', (qw(
      swFwFabricWatchLicense)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  if (defined $self->{swCpuUsage}) {
    $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{swCpuUsage});
    $self->set_thresholds(warning => $self->{swCpuUsageLimit},
        critical => $self->{swCpuUsageLimit});
    $self->add_message($self->check_thresholds($self->{swCpuUsage}));
    $self->add_perfdata(
        label => 'cpu_usage',
        value => $self->{swCpuUsage},
        uom => '%',
    );
  } elsif ($self->{swFwFabricWatchLicense} eq 'swFwNotLicensed') {
    $self->add_unknown('please install a fabric watch license');
  } else {
    my $swFirmwareVersion = $self->get_snmp_object('SW-MIB', 'swFirmwareVersion');
    if ($swFirmwareVersion && $swFirmwareVersion =~ /^v6/) {
      $self->add_ok('cpu usage is not implemented');
    } else {
      $self->add_unknown('cannot aquire cpu usage');
    }
  }
}

package Classes::FabOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{sensor_subsystem} =
      Classes::FabOS::Component::SensorSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{sensor_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{sensor_subsystem}->dump();
}

package Classes::FabOS::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('SW-MIB', [
      ['sensors', 'swSensorTable', 'Classes::FabOS::Component::SensorSubsystem::Sensor'],
  ]);
}

package Classes::FabOS::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s sensor %s (%s) is %s',
      $self->{swSensorType},
      $self->{swSensorIndex},
      $self->{swSensorInfo},
      $self->{swSensorStatus});
  if ($self->{swSensorStatus} eq "faulty") {
    $self->add_critical();
  } elsif ($self->{swSensorStatus} eq "absent") {
  } elsif ($self->{swSensorStatus} eq "unknown") {
    $self->add_critical();
  } else {
    if ($self->{swSensorStatus} eq "nominal") {
      #$self->add_ok();
    } else {
      $self->add_critical();
    }
    $self->add_perfdata(
        label => sprintf('sensor_%s_%s', 
            $self->{swSensorType}, $self->{swSensorIndex}),
        value => $self->{swSensorValue},
    ) if $self->{swSensorType} ne "power-supply";
  }
}


package Classes::FabOS::Component::SensorSubsystem::SensorThreshold;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {
    blacklisted => 0,
    info => undef,
    extendedinfo => undef,
  };
  foreach my $param (qw(entSensorThresholdRelation entSensorThresholdValue
      entSensorThresholdSeverity entSensorThresholdNotificationEnable
      entSensorThresholdEvaluation indices)) {
    $self->{$param} = $params{$param};
  }
  $self->{entPhysicalIndex} = $params{indices}[0];
  $self->{entSensorThresholdIndex} = $params{indices}[1];
  bless $self, $class;
  return $self;
}

package Classes::FabOS;
our @ISA = qw(Classes::Brocade);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::FabOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::FabOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::FabOS::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::HP::Procurve::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('NETSWITCH-MIB', [
      ['mem', 'hpLocalMemTable', 'Classes::HP::Procurve::Component::MemSubsystem::Memory'],
  ]);
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (scalar (@{$self->{mem}}) == 0) {
  } else {
    foreach (@{$self->{mem}}) {
      $_->check();
    }
  }
}


package Classes::HP::Procurve::Component::MemSubsystem::Memory;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{usage} = $self->{hpLocalMemAllocBytes} / 
      $self->{hpLocalMemTotalBytes} * 100;
  $self->add_info(sprintf 'memory %s usage is %.2f',
      $self->{hpLocalMemSlotIndex}, $self->{usage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{usage}));
  $self->add_perfdata(
      label => 'memory_'.$self->{hpLocalMemSlotIndex}.'_usage',
      value => $self->{usage},
      uom => '%',
  );
}

package Classes::HP::Procurve::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('STATISTICS-MIB', (qw(
      hpSwitchCpuStat)));
  if (! defined $self->{hpSwitchCpuStat}) {
    $self->get_snmp_objects('OLD-STATISTICS-MIB', (qw(
        hpSwitchCpuStat)));
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{hpSwitchCpuStat});
  $self->set_thresholds(warning => 80, critical => 90); # maybe lower, because the switching is done in hardware
  $self->add_message($self->check_thresholds($self->{hpSwitchCpuStat}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{hpSwitchCpuStat},
      uom => '%',
  );
}

package Classes::HP::Procurve::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->analyze_and_check_sensor_subsystem('Classes::HP::Procurve::Component::SensorSubsystem');
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}


package Classes::HP::Procurve::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('HP-ICF-CHASSIS-MIB', [
      ['sensors', 'hpicfSensorTable', 'Classes::HP::Procurve::Component::SensorSubsystem::Sensor'],
  ]);
}

sub check {
  my $self = shift;
  $self->add_info('checking sensors');
  if (scalar (@{$self->{sensors}}) == 0) {
    $self->add_ok('no sensors');
  } else {
    foreach (@{$self->{sensors}}) {
      $_->check();
    }
  }
}


package Classes::HP::Procurve::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'sensor %s (%s) is %s',
      $self->{hpicfSensorIndex},
      $self->{hpicfSensorDescr},
      $self->{hpicfSensorStatus});
  if ($self->{hpicfSensorStatus} eq "notPresent") {
  } elsif ($self->{hpicfSensorStatus} eq "bad") {
    $self->add_critical();
  } elsif ($self->{hpicfSensorStatus} eq "warning") {
    $self->add_warning();
  } elsif ($self->{hpicfSensorStatus} eq "good") {
    #$self->add_ok();
  } else {
    $self->add_unknown();
  }
}

package Classes::HP::Procurve;
our @ISA = qw(Classes::HP);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::HP::Procurve::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::HP::Procurve::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::HP::Procurve::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::HP;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
    '1.3.6.1.4.1.11.2.14.11.1.2', # HP-ICF-CHASSIS
    '1.3.6.1.2.1.1.7.11.12.9', # STATISTICS-MIB (old?)
    '1.3.6.1.2.1.1.7.11.12.1', # NETSWITCH-MIB (old?)
    '1.3.6.1.4.1.11.2.14.11.5.1.9', # STATISTICS-MIB
    '1.3.6.1.4.1.11.2.14.11.5.1.1', # NETSWITCH-MIB

);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /Procurve/i) {
    bless $self, 'Classes::HP::Procurve';
    $self->debug('using Classes::HP::Procurve');
  }
  if (ref($self) ne "Classes::HP") {
    $self->init();
  }
}

package Classes::MEOS;
our @ISA = qw(Classes::Brocade);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_and_check_environmental_subsystem();
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_and_check_cpu_subsystem("Classes::UCDMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_and_check_mem_subsystem("Classes::UCDMIB::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

sub analyze_environmental_subsystem {
  my $self = shift;
  $self->{components}->{environmental_subsystem1} =
      Classes::FCMGMT::Component::EnvironmentalSubsystem->new();
  $self->{components}->{environmental_subsystem2} =
      Classes::FCEOS::Component::EnvironmentalSubsystem->new();
}

sub check_environmental_subsystem {
  my $self = shift;
  $self->{components}->{environmental_subsystem1}->check();
  $self->{components}->{environmental_subsystem2}->check();
  if ($self->check_messages()) {
    $self->clear_ok();
  }
  $self->{components}->{environmental_subsystem1}->dump()
      if $self->opts->verbose >= 2;
  $self->{components}->{environmental_subsystem2}->dump()
      if $self->opts->verbose >= 2;
}

package Classes::Brocade;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  foreach ($self->get_snmp_table_objects(
      'ENTITY-MIB', 'entPhysicalTable')) {
    if ($_->{entPhysicalDescr} =~ /Brocade/) {
      $self->{productname} = "FabOS";
    }
  }
  my $swFirmwareVersion = $self->get_snmp_object('SW-MIB', 'swFirmwareVersion');
  if ($swFirmwareVersion && $swFirmwareVersion =~ /^v6/) {
    $self->{productname} = "FabOS"
  }
  if ($self->{productname} =~ /EMC\s*DS.*4700M/i) {
    bless $self, 'Classes::MEOS';
    $self->debug('using Classes::MEOS');
  } elsif ($self->{productname} =~ /EMC\s*DS-24M2/i) {
    bless $self, 'Classes::MEOS';
    $self->debug('using Classes::MEOS');
  } elsif ($self->{productname} =~ /FabOS/i) {
    bless $self, 'Classes::FabOS';
    $self->debug('using Classes::FabOS');
  } elsif ($self->{productname} =~ /ICX6|FastIron/i) {
    bless $self, 'Classes::Foundry';
    $self->debug('using Classes::Foundry');
  } elsif ($self->implements_mib('SW-MIB')) {
    bless $self, 'Classes::FabOS';
    $self->debug('using Classes::FabOS');
  }
  if (ref($self) ne "Classes::Brocade") {
    $self->init();
  } else {
    $self->no_such_mode();
  }
}

package Classes::SecureOS;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    # not sure if this works fa25239716cb74c672f8dd390430dc4056caffa7
    if ($self->implements_mib('FCMGMT-MIB')) {
      $self->analyze_and_check_environmental_subsystem("Classes::FCMGMT::Component::EnvironmentalSubsystem");
    }
    if ($self->implements_mib('HOST-RESOURCES-MIB')) {
      $self->analyze_and_check_environmental_subsystem("Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem");
    }
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::UCDMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::UCDMIB::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::HSRP::Component::HSRPSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{groups} = [];
  if ($self->mode =~ /device::hsrp/) {
    foreach ($self->get_snmp_table_objects(
        'CISCO-HSRP-MIB', 'cHsrpGrpTable')) {
      my $group = Classes::HSRP::Component::HSRPSubsystem::Group->new(%{$_});
      if ($self->filter_name($group->{name})) {
        push(@{$self->{groups}}, $group);
      }
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking hsrp groups');
  if ($self->mode =~ /device::hsrp::list/) {
    foreach (@{$self->{groups}}) {
      $_->list();
    }
  } elsif ($self->mode =~ /device::hsrp/) {
    if (scalar (@{$self->{groups}}) == 0) {
      $self->add_unknown('no hsrp groups');
    } else {
      foreach (@{$self->{groups}}) {
        $_->check();
      }
    }
  }
}


package Classes::HSRP::Component::HSRPSubsystem::Group;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub finish {
  my $self = shift;
  my %params = @_;
  $self->{ifIndex} = $params{indices}->[0];
  $self->{cHsrpGrpNumber} = $params{indices}->[1];
  $self->{name} = $self->{cHsrpGrpNumber}.':'.$self->{ifIndex};
  if ($self->mode =~ /device::hsrp::state/) {
    if (! $self->opts->role()) {
      $self->opts->override_opt('role', 'active');
    }
  }
  return $self;
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::hsrp::state/) {
    $self->add_info(sprintf 'hsrp group %s (interface %s) state is %s (active router is %s, standby router is %s',
        $self->{cHsrpGrpNumber}, $self->{ifIndex},
        $self->{cHsrpGrpStandbyState},
        $self->{cHsrpGrpActiveRouter}, $self->{cHsrpGrpStandbyRouter});
    if ($self->opts->role() eq $self->{cHsrpGrpStandbyState}) {
        $self->add_ok();
    } else {
      $self->add_critical(
          sprintf 'state in group %s (interface %s) is %s instead of %s',
              $self->{cHsrpGrpNumber}, $self->{ifIndex},
              $self->{cHsrpGrpStandbyState},
              $self->opts->role());
    }
  } elsif ($self->mode =~ /device::hsrp::failover/) {
    $self->add_info(sprintf 'hsrp group %s/%s: active node is %s, standby node is %s',
        $self->{cHsrpGrpNumber}, $self->{ifIndex},
        $self->{cHsrpGrpActiveRouter}, $self->{cHsrpGrpStandbyRouter});
    if (my $laststate = $self->load_state( name => $self->{name} )) {
      if ($laststate->{active} ne $self->{cHsrpGrpActiveRouter}) {
        $self->add_critical(sprintf 'hsrp group %s/%s: active node %s --> %s',
            $self->{cHsrpGrpNumber}, $self->{ifIndex},
            $laststate->{active}, $self->{cHsrpGrpActiveRouter});
      }
      if ($laststate->{standby} ne $self->{cHsrpGrpStandbyRouter}) {
        $self->add_warning(sprintf 'hsrp group %s/%s: standby node %s --> %s',
            $self->{cHsrpGrpNumber}, $self->{ifIndex},
            $laststate->{standby}, $self->{cHsrpGrpStandbyRouter});
      }
      if (($laststate->{active} eq $self->{cHsrpGrpActiveRouter}) &&
          ($laststate->{standby} eq $self->{cHsrpGrpStandbyRouter})) {
        $self->add_ok();
      }
    } else {
      $self->add_ok('initializing....');
    }
    $self->save_state( name => $self->{name}, save => {
        active => $self->{cHsrpGrpActiveRouter},
        standby => $self->{cHsrpGrpStandbyRouter},
    });
  }
}

sub list {
  my $self = shift;
  printf "%s %s %s %s\n", $self->{name}, $self->{cHsrpGrpVirtualIpAddr},
      $self->{cHsrpGrpActiveRouter}, $self->{cHsrpGrpStandbyRouter};
}

package Classes::HSRP;
our @ISA = qw(Classes::Device);
use strict;

package Classes::IFMIB::Component::LinkAggregation;
our @ISA = qw(Classes::IFMIB);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub new {
  my $class = shift;
  my $self = {};
  bless $self, $class;
  $self->init();
  return $self;
}

sub init {
  my $self = shift;
  if ($self->opts->name) {
    my @ifs = split(",", $self->opts->name);
    $self->{name} = shift @ifs;
    if ($self->opts->regexp) {
      $self->opts->override_opt('name',
          sprintf "(%s)", join("|", map { sprintf "(%s)", $_ } @ifs));
    } else {
      $self->opts->override_opt('name',
          sprintf "(%s)", join("|", map { sprintf "(^%s\$)", $_ } @ifs));
      $self->opts->override_opt('regexp', 1);
    }
    $self->{components}->{interface_subsystem} =
        Classes::IFMIB::Component::InterfaceSubsystem->new();
  } else {
    #error, must have a name
  }
  if ($self->mode =~ /device::interfaces::aggregation::availability/) {
    $self->{num_if} = scalar(@{$self->{components}->{interface_subsystem}->{interfaces}});
    $self->{down_if} = [grep { $_->{ifOperStatus} eq "down" } @{$self->{components}->{interface_subsystem}->{interfaces}}];
    $self->{num_down_if} = scalar(@{$self->{down_if}});
    $self->{num_up_if} = $self->{num_if} - $self->{num_down_if};
    $self->{availability} = $self->{num_if} ? (100 * $self->{num_up_if} / $self->{num_if}) : 0;
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking link aggregation');
  if (scalar(@{$self->{components}->{interface_subsystem}->{interfaces}}) == 0) {
    $self->add_unknown('no interfaces');
    return;
  }
  if ($self->mode =~ /device::interfaces::aggregation::availability/) {
    my $down_info = scalar(@{$self->{down_if}}) ?
        sprintf " (down: %s)", join(", ", map { $_->{ifDescr} } @{$self->{down_if}}) : "";
    $self->add_info(sprintf 'aggregation %s availability is %.2f%% (%d of %d)%s',
        $self->{name},
        $self->{availability}, $self->{num_up_if}, $self->{num_if},
        $down_info);
    my $cavailability = $self->{num_if} ? (100 * 1 / $self->{num_if}) : 0;
    $cavailability = $cavailability == int($cavailability) ? $cavailability + 1: int($cavailability + 1.0);
    $self->set_thresholds(warning => '100:', critical => $cavailability.':');
    $self->add_message($self->check_thresholds($self->{availability}));
    $self->add_perfdata(
        label => 'aggr_'.$self->{name}.'_availability',
        value => $self->{availability},
        uom => '%',
        warning => $self->{warning},
        critical => $self->{critical},
    );
  }
}


package Classes::IFMIB::Component::InterfaceSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{interfaces} = [];
  if ($self->mode =~ /device::interfaces::list/) {
    $self->update_interface_cache(1);
    foreach my $ifIndex (keys %{$self->{interface_cache}}) {
      my $ifDescr = $self->{interface_cache}->{$ifIndex}->{ifDescr};
      my $ifName = $self->{interface_cache}->{$ifIndex}->{ifName} || '________';
      my $ifAlias = $self->{interface_cache}->{$ifIndex}->{ifAlias} || '________';
      push(@{$self->{interfaces}},
          Classes::IFMIB::Component::InterfaceSubsystem::Interface->new(
              ifIndex => $ifIndex,
              ifDescr => $ifDescr,
              ifName => $ifName,
              ifAlias => $ifAlias,
          ));
    }
  } else {
    $self->update_interface_cache(0);
    #next if $self->opts->can('name') && $self->opts->name && 
    #    $self->opts->name ne $_->{ifDescr};
    # if limited search
    # name is a number -> get_table with extra param
    # name is a regexp -> list of names -> list of numbers
    my @indices = $self->get_interface_indices();
    if (scalar(@indices) > 0) {
      foreach ($self->get_snmp_table_objects(
          'IFMIB', 'ifTable+ifXTable', \@indices)) {
        push(@{$self->{interfaces}},
            Classes::IFMIB::Component::InterfaceSubsystem::Interface->new(%{$_}));
      }
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking interfaces');
  if (scalar(@{$self->{interfaces}}) == 0) {
    $self->add_unknown('no interfaces');
    return;
  }
  if ($self->mode =~ /device::interfaces::list/) {
    foreach (sort {$a->{ifIndex} <=> $b->{ifIndex}} @{$self->{interfaces}}) {
    #foreach (sort @{$self->{interfaces}}) {
      $_->list();
    }
    $self->add_ok("have fun");
  } elsif ($self->mode =~ /device::interfaces::availability/) {
    foreach (@{$self->{interfaces}}) {
      $_->check();
    }
    my $num_interfaces = scalar(@{$self->{interfaces}});
    my $up_interfaces =
        scalar(grep { $_->{ifAdminStatus} eq "up" } @{$self->{interfaces}});
    my $available_interfaces =
        scalar(grep { $_->{ifAvailable} eq "true" } @{$self->{interfaces}});
    $self->add_info(sprintf "%d of %d (%d adm. up) interfaces are available",
        $available_interfaces, $num_interfaces, $up_interfaces);
    $self->set_thresholds(warning => "3:", critical => "2:");
    $self->add_message($self->check_thresholds($available_interfaces));
    $self->add_perfdata(
        label => 'num_interfaces',
        value => $num_interfaces,
        thresholds => 0,
    );
    $self->add_perfdata(
        label => 'available_interfaces',
        value => $available_interfaces,
    );

    printf "%s\n", $self->{info};
    printf "<table style=\"border-collapse:collapse; border: 1px solid black;\">";
    printf "<tr>";
    foreach (qw(Index Descr Type Speed AdminStatus OperStatus Duration Available)) {
      printf "<th style=\"text-align: right; padding-left: 4px; padding-right: 6px;\">%s</th>", $_;
    }
    printf "</tr>";
    my $unique = {};
    foreach (@{$self->{interfaces}}) {
      if (exists $unique->{$_->{ifDescr}}) {
        $unique->{$_->{ifDescr}}++;
      } else {
        $unique->{$_->{ifDescr}} = 0;
      }
    }
    foreach (sort {$a->{ifIndex} <=> $b->{ifIndex}} @{$self->{interfaces}}) {
      if ($unique->{$_->{ifDescr}}) {
        $_->{ifDescr} .= ' '.$_->{ifIndex};
      }
      printf "<tr>";
      printf "<tr style=\"border: 1px solid black;\">";
      foreach my $attr (qw(ifIndex ifDescr ifType ifSpeedText ifAdminStatus ifOperStatus ifStatusDuration ifAvailable)) {
        if ($_->{ifAvailable} eq "false") {
          printf "<td style=\"text-align: right; padding-left: 4px; padding-right: 6px;\">%s</td>", $_->{$attr};
        } else {
          printf "<td style=\"text-align: right; padding-left: 4px; padding-right: 6px; background-color: #00ff33;\">%s</td>", $_->{$attr};
        }
      }
      printf "</tr>";
    }
    printf "</table>\n";
    printf "<!--\nASCII_NOTIFICATION_START\n";
    my $column_length = {};
    foreach (qw(ifIndex ifDescr ifType ifSpeed ifAdminStatus ifOperStatus Duration ifAvailable ifSpeedText ifStatusDuration)) {
      $column_length->{$_} = length($_);
    }
    foreach (sort {$a->{ifIndex} <=> $b->{ifIndex}} @{$self->{interfaces}}) {
      if ($unique->{$_->{ifDescr}}) {
        $_->{ifDescr} .= ' '.$_->{ifIndex};
      }
      foreach my $attr (qw(ifIndex ifDescr ifType ifSpeedText ifAdminStatus ifOperStatus ifStatusDuration ifAvailable)) {
        if (length($_->{$attr}) > $column_length->{$attr}) {
          $column_length->{$attr} = length($_->{$attr});
        }
      }
    }
    foreach (qw(ifIndex ifDescr ifType ifSpeed ifAdminStatus ifOperStatus Duration ifStatusDuration ifAvailable ifSpeedText)) {
      $column_length->{$_} = "%".($column_length->{$_} + 3)."s|";
    }
    $column_length->{ifSpeed} = $column_length->{ifSpeedText};
    $column_length->{Duration} = $column_length->{ifStatusDuration};
    foreach (qw(ifIndex ifDescr ifType ifSpeed ifAdminStatus ifOperStatus Duration ifAvailable)) {
      printf $column_length->{$_}, $_;
    }
    printf "\n";
    foreach (sort {$a->{ifIndex} <=> $b->{ifIndex}} @{$self->{interfaces}}) {
      if ($unique->{$_->{ifDescr}}) {
        $_->{ifDescr} .= ' '.$_->{ifIndex};
      }
      foreach my $attr (qw(ifIndex ifDescr ifType ifSpeedText ifAdminStatus ifOperStatus ifStatusDuration ifAvailable)) {
        printf $column_length->{$attr}, $_->{$attr};
      }
      printf "\n";
    }
    printf "ASCII_NOTIFICATION_END\n-->\n";
  } else {
    if (scalar (@{$self->{interfaces}}) == 0) {
    } else {
      my $unique = {};
      foreach (@{$self->{interfaces}}) {
        if (exists $unique->{$_->{ifDescr}}) {
          $unique->{$_->{ifDescr}}++;
        } else {
          $unique->{$_->{ifDescr}} = 0;
        }
      }
      foreach (sort {$a->{ifIndex} <=> $b->{ifIndex}} @{$self->{interfaces}}) {
        if ($unique->{$_->{ifDescr}}) {
          $_->{ifDescr} .= ' '.$_->{ifIndex};
        }
        $_->check();
      }
      if ($self->opts->report eq "short") {
        $self->clear_ok();
        $self->add_ok('no problems') if ! $self->check_messages();
      }
    }
  }
}

sub update_interface_cache {
  my $self = shift;
  my $force = shift;
  my $statefile = $self->create_interface_cache_file();
  $self->get_snmp_objects('IFMIB', qw(ifTableLastChange));
  # "The value of sysUpTime at the time of the last creation or
  # deletion of an entry in the ifTable. If the number of
  # entries has been unchanged since the last re-initialization
  # of the local network management subsystem, then this object
  # contains a zero value."
  $self->{ifTableLastChange} ||= 0;
  $self->{ifCacheLastChange} = -f $statefile ? (stat $statefile)[9] : 0;
  $self->{bootTime} = time - $self->uptime();
  $self->{ifTableLastChange} = $self->{bootTime} + $self->timeticks($self->{ifTableLastChange});
  my $update_deadline = time - 3600;
  my $must_update = 0;
  if ($self->{ifCacheLastChange} < $update_deadline) {
    # file older than 1h or file does not exist
    $must_update = 1;
    $self->debug(sprintf 'interface cache is older than 1h (%s < %s)',
        scalar localtime $self->{ifCacheLastChange}, scalar localtime $update_deadline);
  }
  if ($self->{ifTableLastChange} >= $self->{ifCacheLastChange}) {
    $must_update = 1;
    $self->debug(sprintf 'interface table changes newer than cache file (%s >= %s)',
        scalar localtime $self->{ifCacheLastChange}, scalar localtime $self->{ifCacheLastChange});
  }
  if ($force) {
    $must_update = 1;
    $self->debug(sprintf 'interface table update forced');
  }
  if ($must_update) {
    $self->debug('update of interface cache');
    $self->{interface_cache} = {};
    foreach ($self->get_snmp_table_objects('MINI-IFMIB', 'ifTable+ifXTable', [-1])) {
      # neuerdings index+descr, weil die drecksscheiss allied telesyn ports
      # alle gleich heissen
      # und noch so ein hirnbrand: --mode list-interfaces
      # 000003 Adaptive Security Appliance 'GigabitEthernet0/0' interface
      # ....
      # der ASA-schlonz ist ueberfluessig, also brauchen wir eine hintertuer
      # um die namen auszuputzen
      if ($self->opts->name2 && $self->opts->name2 =~ /\(\.\*\?*\)/) {
        if ($_->{ifDescr} =~ $self->opts->name2) {
          $_->{ifDescr} = $1;
        }
      }
      $self->{interface_cache}->{$_->{ifIndex}}->{ifDescr} = unpack("Z*", $_->{ifDescr});
      $self->{interface_cache}->{$_->{ifIndex}}->{ifName} = unpack("Z*", $_->{ifName}) if exists $_->{ifName};
      $self->{interface_cache}->{$_->{ifIndex}}->{ifAlias} = unpack("Z*", $_->{ifAlias}) if exists $_->{ifAlias};
    }
    $self->save_interface_cache();
  }
  $self->load_interface_cache();
}

sub save_interface_cache {
  my $self = shift;
  $self->create_statefilesdir();
  my $statefile = $self->create_interface_cache_file();
  my $tmpfile = $self->statefilesdir().'/check_nwc_health_tmp_'.$$;
  my $fh = IO::File->new();
  $fh->open(">$tmpfile");
  $fh->print(Data::Dumper::Dumper($self->{interface_cache}));
  $fh->flush();
  $fh->close();
  my $ren = rename $tmpfile, $statefile;
  $self->debug(sprintf "saved %s to %s",
      Data::Dumper::Dumper($self->{interface_cache}), $statefile);

}

sub load_interface_cache {
  my $self = shift;
  my $statefile = $self->create_interface_cache_file();
  if ( -f $statefile) {
    our $VAR1;
    eval {
      require $statefile;
    };
    if($@) {
      printf "rumms\n";
    }
    $self->debug(sprintf "load %s", Data::Dumper::Dumper($VAR1));
    $self->{interface_cache} = $VAR1;
    eval {
      foreach (keys %{$self->{interface_cache}}) {
        /^\d+$/ || die "newrelease";
      }
    };
    if($@) {
      $self->{interface_cache} = {};
      unlink $statefile;
      delete $INC{$statefile};
      $self->update_interface_cache(1);
    }
  }
}

sub get_interface_indices {
  my $self = shift;
  my @indices = ();
  foreach my $ifIndex (keys %{$self->{interface_cache}}) {
    my $ifDescr = $self->{interface_cache}->{$ifIndex}->{ifDescr};
    my $ifAlias = $self->{interface_cache}->{$ifIndex}->{ifAlias} || '________';
    if ($self->opts->name) {
      if ($self->opts->regexp) {
        my $pattern = $self->opts->name;
        if ($ifDescr =~ /$pattern/i) {
          push(@indices, [$ifIndex]);
        }
      } else {
        if ($self->opts->name =~ /^\d+$/) {
          if ($ifIndex == 1 * $self->opts->name) {
            push(@indices, [1 * $self->opts->name]);
          }
        } else {
          if (lc $ifDescr eq lc $self->opts->name) {
            push(@indices, [$ifIndex]);
          }
        }
      }
    } else {
      push(@indices, [$ifIndex]);
    }
  }
  return @indices;
}


package Classes::IFMIB::Component::InterfaceSubsystem::Interface;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {
    ifTable => $params{ifTable},
    ifEntry => $params{ifEntry},
    ifIndex => $params{ifIndex},
    ifDescr => $params{ifDescr},
    ifType => $params{ifType},
    ifMtu => $params{ifMtu},
    ifSpeed => $params{ifSpeed},
    ifPhysAddress => $params{ifPhysAddress},
    ifAdminStatus => $params{ifAdminStatus},
    ifOperStatus => $params{ifOperStatus},
    ifLastChange => $params{ifLastChange},
    ifInOctets => $params{ifInOctets},
    ifInUcastPkts => $params{ifInUcastPkts},
    ifInNUcastPkts => $params{ifInNUcastPkts},
    ifInDiscards => $params{ifInDiscards},
    ifInErrors => $params{ifInErrors},
    ifInUnknownProtos => $params{ifInUnknownProtos},
    ifOutOctets => $params{ifOutOctets},
    ifOutUcastPkts => $params{ifOutUcastPkts},
    ifOutNUcastPkts => $params{ifOutNUcastPkts},
    ifOutDiscards => $params{ifOutDiscards},
    ifOutErrors => $params{ifOutErrors},
    ifOutQLen => $params{ifOutQLen},
    ifSpecific => $params{ifSpecific},
    blacklisted => 0,
    info => undef,
    extendedinfo => undef,
  };
  foreach my $key (keys %{$self}) {
    next if $key !~ /^if/;
    $self->{$key} = 0 if ! defined $params{$key};
  }
  $self->{ifDescr} = unpack("Z*", $self->{ifDescr}); # windows has trailing nulls
  bless $self, $class;
  if ($self->opts->name2 && $self->opts->name2 =~ /\(\.\*\?*\)/) {
    if ($self->{ifDescr} =~ $self->opts->name2) {
      $self->{ifDescr} = $1;
    }
  }
  # Manche Stinkstiefel haben ifName, ifHighSpeed und z.b. ifInMulticastPkts,
  # aber keine ifHC*Octets. Gesehen bei Cisco Switch Interface Nul0 o.ae.
  if ($params{ifName} && defined $params{ifHCInOctets} && 
      defined $params{ifHCOutOctets} && $params{ifHCInOctets} ne "noSuchObject") {
    my $self64 = {
      ifName => $params{ifName},
      ifInMulticastPkts => $params{ifInMulticastPkts},
      ifInBroadcastPkts => $params{ifInBroadcastPkts},
      ifOutMulticastPkts => $params{ifOutMulticastPkts},
      ifOutBroadcastPkts => $params{ifOutBroadcastPkts},
      ifHCInOctets => $params{ifHCInOctets},
      ifHCInUcastPkts => $params{ifHCInUcastPkts},
      ifHCInMulticastPkts => $params{ifHCInMulticastPkts},
      ifHCInBroadcastPkts => $params{ifHCInBroadcastPkts},
      ifHCOutOctets => $params{ifHCOutOctets},
      ifHCOutUcastPkts => $params{ifHCOutUcastPkts},
      ifHCOutMulticastPkts => $params{ifHCOutMulticastPkts},
      ifHCOutBroadcastPkts => $params{ifHCOutBroadcastPkts},
      ifLinkUpDownTrapEnable => $params{ifLinkUpDownTrapEnable},
      ifHighSpeed => $params{ifHighSpeed},
      ifPromiscuousMode => $params{ifPromiscuousMode},
      ifConnectorPresent => $params{ifConnectorPresent},
      ifAlias => $params{ifAlias} || $params{ifName}, # kommt vor bei linux lo
      ifCounterDiscontinuityTime => $params{ifCounterDiscontinuityTime},
    };
    map { $self->{$_} = $self64->{$_} } keys %{$self64};
    $self->{ifName} = unpack("Z*", $self->{ifName});
    $self->{ifAlias} = unpack("Z*", $self->{ifAlias});
    bless $self, 'Classes::IFMIB::Component::InterfaceSubsystem::Interface::64bit';
  }
  $self->init();
  return $self;
}

sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::usage/) {
    $self->valdiff({name => $self->{ifIndex}.'#'.$self->{ifDescr}}, qw(ifInOctets ifOutOctets));
    if ($self->{ifSpeed} == 0) {
      # vlan graffl
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    } else {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{maxInputRate} = $self->{ifSpeed};
      $self->{maxOutputRate} = $self->{ifSpeed};
    }
    if (defined $self->opts->ifspeedin) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedin);
      $self->{maxInputRate} = $self->opts->ifspeedin;
    }
    if (defined $self->opts->ifspeedout) {
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedout);
      $self->{maxOutputRate} = $self->opts->ifspeedout;
    }
    if (defined $self->opts->ifspeed) {
      $self->{inputUtilization} = $self->{delta_ifInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{outputUtilization} = $self->{delta_ifOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{maxInputRate} = $self->opts->ifspeed;
      $self->{maxOutputRate} = $self->opts->ifspeed;
    }
    $self->{inputRate} = $self->{delta_ifInOctets} / $self->{delta_timestamp};
    $self->{outputRate} = $self->{delta_ifOutOctets} / $self->{delta_timestamp};
    $self->{maxInputRate} /= 8; # auf octets umrechnen wie die in/out
    $self->{maxOutputRate} /= 8;
    my $factor = 1/8; # default Bits
    if ($self->opts->units) {
      if ($self->opts->units eq "GB") {
        $factor = 1024 * 1024 * 1024;
      } elsif ($self->opts->units eq "MB") {
        $factor = 1024 * 1024;
      } elsif ($self->opts->units eq "KB") {
        $factor = 1024;
      } elsif ($self->opts->units eq "GBi") {
        $factor = 1024 * 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "MBi") {
        $factor = 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "KBi") {
        $factor = 1024 / 8;
      } elsif ($self->opts->units eq "B") {
        $factor = 1;
      } elsif ($self->opts->units eq "Bit") {
        $factor = 1/8;
      }
    }
    $self->{inputRate} /= $factor;
    $self->{outputRate} /= $factor;
    $self->{maxInputRate} /= $factor;
    $self->{maxOutputRate} /= $factor;
    if ($self->{ifOperStatus} eq 'down') {
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{inputRate} = 0;
      $self->{outputRate} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    }
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInErrors ifOutErrors));
    $self->{inputErrorRate} = $self->{delta_ifInErrors} 
        / $self->{delta_timestamp};
    $self->{outputErrorRate} = $self->{delta_ifOutErrors} 
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->valdiff({name => $self->{ifDescr}}, qw(ifInDiscards ifOutDiscards));
    $self->{inputDiscardRate} = $self->{delta_ifInDiscards} 
        / $self->{delta_timestamp};
    $self->{outputDiscardRate} = $self->{delta_ifOutDiscards} 
        / $self->{delta_timestamp};
  } elsif ($self->mode =~ /device::interfaces::operstatus/) {
  } elsif ($self->mode =~ /device::interfaces::availability/) {
    $self->{ifStatusDuration} = 
        $self->uptime() - $self->timeticks($self->{ifLastChange});
    $self->opts->override_opt('lookback', 1800) if ! $self->opts->lookback;
    if ($self->{ifAdminStatus} eq "down") {
      $self->{ifAvailable} = "true";
    } elsif ($self->{ifAdminStatus} eq "up" && $self->{ifOperStatus} ne "up" &&
        $self->{ifStatusDuration} > $self->opts->lookback) {
      # and ifLastChange schon ein wenig laenger her
      $self->{ifAvailable} = "true";
    } else {
      $self->{ifAvailable} = "false";
    }
    my $gb = 1000 * 1000 * 1000;
    my $mb = 1000 * 1000;
    my $kb = 1000;
    my $speed = $self->{ifHighSpeed} ? 
        ($self->{ifHighSpeed} * $mb) : $self->{ifSpeed};
    if ($speed >= $gb) {
      $self->{ifSpeedText} = sprintf "%.2fGB", $speed / $gb;
    } elsif ($speed >= $mb) {
      $self->{ifSpeedText} = sprintf "%.2fMB", $speed / $mb;
    } elsif ($speed >= $kb) {
      $self->{ifSpeedText} = sprintf "%.2fKB", $speed / $kb;
    } else {
      $self->{ifSpeedText} = sprintf "%.2fB", $speed;
    }
    $self->{ifSpeedText} =~ s/\.00//g;
  }
  return $self;
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::usage/) {
    $self->add_info(sprintf 'interface %s usage is in:%.2f%% (%s) out:%.2f%% (%s)%s',
        $self->{ifDescr}, 
        $self->{inputUtilization}, 
        sprintf("%.2f%s/s", $self->{inputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')),
        $self->{outputUtilization},
        sprintf("%.2f%s/s", $self->{outputRate},
            ($self->opts->units ? $self->opts->units : 'Bits')),
        $self->{ifOperStatus} eq 'down' ? ' (down)' : '');
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        warning => 80,
        critical => 90
    );
    my $in = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization}
    );
    $self->set_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        warning => 80,
        critical => 90
    );
    my $out = $self->check_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization}
    );
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_in',
        value => $self->{inputUtilization},
        uom => '%',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_usage_out',
        value => $self->{outputUtilization},
        uom => '%',
    );

    my ($inwarning, $incritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_in',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_in',
        value => $self->{inputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxInputRate},
        warning => $self->{maxInputRate} / 100 * $inwarning,
        critical => $self->{maxInputRate} / 100 * $incritical,
    );
    my ($outwarning, $outcritical) = $self->get_thresholds(
        metric => $self->{ifDescr}.'_usage_out',
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_traffic_out',
        value => $self->{outputRate},
        uom => $self->opts->units,
        places => 2,
        min => 0,
        max => $self->{maxOutputRate},
        warning => $self->{maxOutputRate} / 100 * $outwarning,
        critical => $self->{maxOutputRate} / 100 * $outcritical,
    );
  } elsif ($self->mode =~ /device::interfaces::errors/) {
    $self->add_info(sprintf 'interface %s errors in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputErrorRate} , $self->{outputErrorRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputErrorRate});
    my $out = $self->check_thresholds($self->{outputErrorRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_in',
        value => $self->{inputErrorRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_errors_out',
        value => $self->{outputErrorRate},
    );
  } elsif ($self->mode =~ /device::interfaces::discards/) {
    $self->add_info(sprintf 'interface %s discards in:%.2f/s out:%.2f/s ',
        $self->{ifDescr},
        $self->{inputDiscardRate} , $self->{outputDiscardRate});
    $self->set_thresholds(warning => 1, critical => 10);
    my $in = $self->check_thresholds($self->{inputDiscardRate});
    my $out = $self->check_thresholds($self->{outputDiscardRate});
    my $level = ($in > $out) ? $in : ($out > $in) ? $out : $in;
    $self->add_message($level);
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_in',
        value => $self->{inputDiscardRate},
    );
    $self->add_perfdata(
        label => $self->{ifDescr}.'_discards_out',
        value => $self->{outputDiscardRate},
    );
  } elsif ($self->mode =~ /device::interfaces::operstatus/) {
    #rfc2863
    #(1)   if ifAdminStatus is not down and ifOperStatus is down then a
    #     fault condition is presumed to exist on the interface.
    #(2)   if ifAdminStatus is down, then ifOperStatus will normally also
    #     be down (or notPresent) i.e., there is not (necessarily) a
    #     fault condition on the interface.
    # --warning onu,anu
    # Admin: admindown,admin
    # Admin: --warning 
    #        --critical admindown
    # !ad+od  ad+!(od*on)
    # warn & warnbitfield
#    if ($self->opts->critical) {
#      if ($self->opts->critical =~ /^u/) {
#      } elsif ($self->opts->critical =~ /^u/) {
#      }
#    }
#    if ($self->{ifOperStatus} ne 'up') {
#      }
#    } 
    $self->add_info(sprintf '%s is %s/%s',
        $self->{ifDescr}, $self->{ifOperStatus}, $self->{ifAdminStatus});
    $self->add_ok();
    if ($self->{ifOperStatus} eq 'down' && $self->{ifAdminStatus} ne 'down') {
      $self->add_critical(
          sprintf 'fault condition is presumed to exist on %s',
          $self->{ifDescr});
    }
    if ($self->{ifAdminStatus} eq 'down') {
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : 2,
          sprintf '%s is admin down', $self->{ifDescr});
    }
  } elsif ($self->mode =~ /device::interfaces::availability/) {
    $self->{ifStatusDuration} = 
        $self->human_timeticks($self->{ifStatusDuration});
    $self->add_info(sprintf '%s is %savailable (%s/%s, since %s)',
        $self->{ifDescr}, ($self->{ifAvailable} eq "true" ? "" : "un"),
        $self->{ifOperStatus}, $self->{ifAdminStatus},
        $self->{ifStatusDuration});
  }
}

sub list {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::listdetail/) {
    my $cL2L3IfModeOper = $self->get_snmp_object('CISCO-L2L3-INTERFACE-CONFIG-MIB', 'cL2L3IfModeOper', $self->{ifIndex}) || "unknown";
    my $vlanTrunkPortDynamicStatus = $self->get_snmp_object('CISCO-VTP-MIB', 'vlanTrunkPortDynamicStatus', $self->{ifIndex}) || "unknown";
    printf "%06d %s %s %s\n", $self->{ifIndex}, $self->{ifDescr},
        $cL2L3IfModeOper, $vlanTrunkPortDynamicStatus;
  } else {
    printf "%06d %s\n", $self->{ifIndex}, $self->{ifDescr};
  }
}


package Classes::IFMIB::Component::InterfaceSubsystem::Interface::64bit;
our @ISA = qw(Classes::IFMIB::Component::InterfaceSubsystem::Interface);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::usage/) {
    $self->valdiff({name => $self->{ifIndex}.'#'.$self->{ifDescr}}, qw(ifHCInOctets ifHCOutOctets));
    # ifSpeed = Bits/sec
    # ifHighSpeed = 1000000Bits/sec
    if ($self->{ifSpeed} == 0) {
      # vlan graffl
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    } elsif ($self->{ifSpeed} == 4294967295) {
      $self->{inputUtilization} = $self->{delta_ifHCInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifHighSpeed} * 1000000);
      $self->{outputUtilization} = $self->{delta_ifHCOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifHighSpeed} * 1000000);
      $self->{maxInputRate} = $self->{ifHighSpeed} * 1000000;
      $self->{maxOutputRate} = $self->{ifHighSpeed} * 1000000;
    } else {
      $self->{inputUtilization} = $self->{delta_ifHCInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{outputUtilization} = $self->{delta_ifHCOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->{ifSpeed});
      $self->{maxInputRate} = $self->{ifSpeed};
      $self->{maxOutputRate} = $self->{ifSpeed};
    }
    if (defined $self->opts->ifspeedin) {
      $self->{inputUtilization} = $self->{delta_ifHCInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedin);
      $self->{maxInputRate} = $self->opts->ifspeedin;
    }
    if (defined $self->opts->ifspeedout) {
      $self->{outputUtilization} = $self->{delta_ifHCOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeedout);
      $self->{maxOutputRate} = $self->opts->ifspeedout;
    }
    if (defined $self->opts->ifspeed) {
      $self->{inputUtilization} = $self->{delta_ifHCInOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{outputUtilization} = $self->{delta_ifHCOutOctets} * 8 * 100 /
          ($self->{delta_timestamp} * $self->opts->ifspeed);
      $self->{maxInputRate} = $self->opts->ifspeed;
      $self->{maxOutputRate} = $self->opts->ifspeed;
    }
    $self->{inputRate} = $self->{delta_ifHCInOctets} / $self->{delta_timestamp};
    $self->{outputRate} = $self->{delta_ifHCOutOctets} / $self->{delta_timestamp};
    $self->{maxInputRate} /= 8; # auf octets umrechnen wie die in/out
    $self->{maxOutputRate} /= 8;
    my $factor = 1/8; # default Bits
    if ($self->opts->units) {
      if ($self->opts->units eq "GB") {
        $factor = 1024 * 1024 * 1024;
      } elsif ($self->opts->units eq "MB") {
        $factor = 1024 * 1024;
      } elsif ($self->opts->units eq "KB") {
        $factor = 1024;
      } elsif ($self->opts->units eq "GBi") {
        $factor = 1024 * 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "MBi") {
        $factor = 1024 * 1024 / 8;
      } elsif ($self->opts->units eq "KBi") {
        $factor = 1024 / 8;
      } elsif ($self->opts->units eq "B") {
        $factor = 1;
      } elsif ($self->opts->units eq "Bit") {
        $factor = 1/8;
      }
    }
    $self->{inputRate} /= $factor;
    $self->{outputRate} /= $factor;
    $self->{maxInputRate} /= $factor;
    $self->{maxOutputRate} /= $factor;
    if ($self->{ifOperStatus} eq 'down') {
      $self->{inputUtilization} = 0;
      $self->{outputUtilization} = 0;
      $self->{inputRate} = 0;
      $self->{outputRate} = 0;
      $self->{maxInputRate} = 0;
      $self->{maxOutputRate} = 0;
    }
  } else {
    $self->SUPER::init();
  }
  return $self;
}

package Classes::IFMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::IPFORWARDMIB::Component::RoutingSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

# ipRouteTable		1.3.6.1.2.1.4.21 
# replaced by
# ipForwardTable	1.3.6.1.2.1.4.24.2
# deprecated by
# ipCidrRouteTable	1.3.6.1.2.1.4.24.4
# deprecated by the ip4/6-neutral
# inetCidrRouteTable	1.3.6.1.2.1.4.24.7

sub init {
  my $self = shift;
  $self->{interfaces} = [];
  $self->get_snmp_tables('IP-FORWARD-MIB', [
      ['routes', 'inetCidrRouteTable', 'Classes::IPFORWARDMIB::Component::RoutingSubsystem::inetCidrRoute' ],
  ]);
  if (! @{$self->{routes}}) {
    $self->get_snmp_tables('IP-FORWARD-MIB', [
        ['routes', 'ipCidrRouteTable', 'Classes::IPFORWARDMIB::Component::RoutingSubsystem::ipCidrRoute',
            sub {
              my $o = shift;
              if ($o->opts->name && $o->opts->name =~ /\//) {
                my ($dest, $cidr) = split(/\//, $o->opts->name);
                my $bits = ( 2 ** (32 - $cidr) ) - 1;
                my ($full_mask) = unpack("N", pack("C4", split(/\./, '255.255.255.255')));
                my $netmask = join('.', unpack("C4", pack("N", ($full_mask ^ $bits))));
                return defined $o->{ipCidrRouteDest} && (
                    $o->filter_namex($dest, $o->{ipCidrRouteDest}) &&
                    $o->filter_namex($netmask, $o->{ipCidrRouteMask}) &&
                    $o->filter_name2($o->{ipCidrRouteNextHop})
                );
              } else {
                return defined $o->{ipCidrRouteDest} && (
                    $o->filter_name($o->{ipCidrRouteDest}) &&
                    $o->filter_name2($o->{ipCidrRouteNextHop})
                );
              }
            }
        ],
    ]);
  }
  # deprecated
  #$self->get_snmp_tables('IP-FORWARD-MIB', [
  #    ['routes', 'ipForwardTable', 'Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route' ],
  #]);
  #$self->get_snmp_tables('IP-MIB', [
  #    ['routes', 'ipRouteTable', 'Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route' ],
  #]);
}

sub check {
  my $self = shift;
  $self->add_info('checking routes');
  if ($self->mode =~ /device::routes::list/) {
    foreach (@{$self->{routes}}) {
      $_->list();
    }
    $self->add_ok("have fun");
  } elsif ($self->mode =~ /device::routes::count/) {
    if (! $self->opts->name && $self->opts->name2) {
      $self->add_info(sprintf "found %d routes via next hop %s",
          scalar(@{$self->{routes}}), $self->opts->name2);
    } elsif ($self->opts->name && ! $self->opts->name2) {
      $self->add_info(sprintf "found %d routes to dest %s",
          scalar(@{$self->{routes}}), $self->opts->name);
    } elsif ($self->opts->name && $self->opts->name2) {
      $self->add_info(sprintf "found %d routes to dest %s via hop %s",
          scalar(@{$self->{routes}}), $self->opts->name, $self->opts->name2);
    } else {
      $self->add_info(sprintf "found %d routes",
          scalar(@{$self->{routes}}));
    }
    $self->set_thresholds(warning => '1:', critical => '1:');
    $self->add_message($self->check_thresholds(scalar(@{$self->{routes}})));
    $self->add_perfdata(
        label => 'routes',
        value => scalar(@{$self->{routes}}),
    );
  }
}


package Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

package Classes::IPFORWARDMIB::Component::RoutingSubsystem::ipRoute;
our @ISA = qw(Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route);

package Classes::IPFORWARDMIB::Component::RoutingSubsystem::ipCidrRoute;
our @ISA = qw(Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route);

sub finish {
  my $self = shift;
  if (! defined $self->{ipCidrRouteDest}) {
    # we can reconstruct a few attributes from the index
    # one customer only made ipCidrRouteStatus visible
    $self->{ipCidrRouteDest} = join(".", map { $self->{indices}->[$_] } (0, 1, 2, 3));
    $self->{ipCidrRouteMask} = join(".", map { $self->{indices}->[$_] } (4, 5, 6, 7));
    $self->{ipCidrRouteTos} = $self->{indices}->[8];
    $self->{ipCidrRouteNextHop} = join(".", map { $self->{indices}->[$_] } (9, 10, 11, 12));
    $self->{ipCidrRouteType} = "other"; # maybe not, who cares
    $self->{ipCidrRouteProto} = "other"; # maybe not, who cares
  }
}

sub list {
  my $self = shift;
  printf "%16s %16s %16s %11s %7s\n", 
      $self->{ipCidrRouteDest}, $self->{ipCidrRouteMask},
      $self->{ipCidrRouteNextHop}, $self->{ipCidrRouteProto},
      $self->{ipCidrRouteType};
}

package Classes::IPFORWARDMIB::Component::RoutingSubsystem::inetCidrRoute;
our @ISA = qw(Classes::IPFORWARDMIB::Component::RoutingSubsystem::Route);

sub finish {
  my $self = shift;
  # http://www.mibdepot.com/cgi-bin/vendor_index.cgi?r=ietf_rfcs
  # INDEX { inetCidrRouteDestType, inetCidrRouteDest, inetCidrRoutePfxLen, inetCidrRoutePolicy, inetCidrRouteNextHopType, inetCidrRouteNextHop }
  $self->{inetCidrRouteDestType} = $self->mibs_and_oids_definition(
      'RFC4001-MIB', 'inetAddressType', $self->{indices}->[0]);
  if ($self->{inetCidrRouteDestType} eq "ipv4") {
    $self->{inetCidrRouteDest} = $self->mibs_and_oids_definition(
      'RFC4001-MIB', 'inetAddress', $self->{indices}->[1],
      $self->{indices}->[2], $self->{indices}->[3], $self->{indices}->[4]);
  } elsif ($self->{inetCidrRouteDestType} eq "ipv4") {
    $self->{inetCidrRoutePfxLen} = $self->mibs_and_oids_definition(
      'RFC4001-MIB', 'inetAddress', $self->{indices}->[1],
      $self->{indices}->[2], $self->{indices}->[3], $self->{indices}->[4]);
    
  }
}

package Classes::IPFORWARDMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::IPMIB::Component::RoutingSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{interfaces} = [];
  $self->get_snmp_tables('IP-MIB', [
      ['routes', 'ipRouteTable', 'Classes::IPMIB::Component::RoutingSubsystem::Route' ],
  ]);
}

sub check {
  my $self = shift;
  $self->add_info('checking routes');
  if ($self->mode =~ /device::routes::list/) {
    foreach (@{$self->{routes}}) {
printf "%s\n", Data::Dumper::Dumper($_);
      $_->list();
    }
    $self->add_ok("have fun");
  }
}


package Classes::IPMIB::Component::RoutingSubsystem::Route;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);

package Classes::IPMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::HOSTRESOURCESMIB::Component::DiskSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('HOST-RESOURCES-MIB', [
      ['storages', 'hrStorageTable', 'Classes::HOSTRESOURCESMIB::Component::DiskSubsystem::Storage', sub { return shift->{hrStorageType} eq 'hrStorageFixedDisk' } ],
  ]);
}

package Classes::HOSTRESOURCESMIB::Component::DiskSubsystem::Storage;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  my $free = 100 - 100 * $self->{hrStorageUsed} / $self->{hrStorageSize};
  $self->add_info(sprintf 'storage %s (%s) has %.2f%% free space left',
      $self->{hrStorageIndex},
      $self->{hrStorageDescr},
      $free);
  if ($self->{hrStorageDescr} eq "/dev" || $self->{hrStorageDescr} =~ /.*cdrom.*/) {
    # /dev is usually full, so we ignore it.
    $self->set_thresholds(metric => sprintf('%s_free_pct', $self->{hrStorageDescr}),
        warning => '0:', critical => '0:');
  } else {
    $self->set_thresholds(metric => sprintf('%s_free_pct', $self->{hrStorageDescr}),
        warning => '10:', critical => '5:');
  }
  $self->add_message($self->check_thresholds(metric => sprintf('%s_free_pct', $self->{hrStorageDescr}),
      value => $free));
  $self->add_perfdata(
      label => sprintf('%s_free_pct', $self->{hrStorageDescr}),
      value => $free,
      uom => '%',
  );
}

package Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{disk_subsystem} =
      Classes::HOSTRESOURCESMIB::Component::DiskSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{disk_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{disk_subsystem}->dump();
}

package Classes::HOSTRESOURCESMIB::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $idx = 0;
  $self->get_snmp_tables('HOST-RESOURCES-MIB', [
      ['cpus', 'hrProcessorTable', 'Classes::HOSTRESOURCESMIB::Component::CpuSubsystem::Cpu'],
  ]);
  foreach (@{$self->{cpus}}) {
    $_->{hrProcessorIndex} = $idx++;
  }
}

package Classes::HOSTRESOURCESMIB::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s is %.2f%%',
      $self->{hrProcessorIndex},
      $self->{hrProcessorLoad});
  $self->set_thresholds(warning => '80', critical => '90');
  $self->add_message($self->check_thresholds($self->{hrProcessorLoad}));
  $self->add_perfdata(
      label => sprintf('cpu_%s_usage', $self->{hrProcessorIndex}),
      value => $self->{hrProcessorLoad},
      uom => '%',
  );
}

package Classes::HOSTRESOURCESMIB::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('HOST-RESOURCES-MIB', [
      ['storagesram', 'hrStorageTable', 'Classes::HOSTRESOURCESMIB::Component::DiskSubsystem::Storage', sub { return shift->{hrStorageType} eq 'hrStorageRam' } ],
  ]);
}

package Classes::HOSTRESOURCESMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::LMSENSORSMIB::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{fan_subsystem} =
      Classes::LMSENSORSMIB::Component::FanSubsystem->new();
  $self->{temperature_subsystem} =
      Classes::LMSENSORSMIB::Component::TemperatureSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{temperature_subsystem}->check();
}

sub dump {
  my $self = shift;
  $self->{temperature_subsystem}->dump();
}

package Classes::LMSENSORSMIB::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('LM-SENSORS-MIB', [
      ['fans', 'lmFanSensorsTable', 'Classes::LMSENSORSMIB::Component::FanSubsystem::Fan'],
  ]);
}

package Classes::LMSENSORSMIB::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{ciscoEnvMonFanStatusIndex} ||= 0;
  $self->add_info(sprintf 'fan %d is %s',
      $self->{lmFanSensorsDevice},
      $self->{lmFanSensorsValue});
  $self->add_ok();
}

package Classes::LMSENSORSMIB::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('LM-SENSORS-MIB', [
      ['temperatures', 'lmTempSensorsTable', 'Classes::LMSENSORSMIB::Component::TemperatureSubsystem::Temperature'],
  ]);
}

package Classes::LMSENSORSMIB::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{lmTempSensorsValue} /= 1000;
}

sub check {
  my $self = shift;
  $self->{ciscoEnvMonTemperatureStatusIndex} ||= 0;
  $self->add_info(sprintf 'temp %s is %.2fC',
      $self->{lmTempSensorsDevice},
      $self->{lmTempSensorsValue});
  $self->add_ok();
  $self->add_perfdata(
      label => sprintf('temp_%s', $self->{lmTempSensorsDevice}),
      value => $self->{lmTempSensorsValue},
  );
}

package Classes::LMSENSORSMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::ENTITYSENSORMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ENTITY-MIB', [
    ['entities', 'entPhysicalTable', 'Monitoring::GLPlugin::TableItem', sub { my $o = shift; $o->{entPhysicalClass} eq 'sensor';}],
  ]);
  $self->get_snmp_tables('ENTITY-SENSOR-MIB', [
    ['sensors', 'entPhySensorTable', 'Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor' ],
  ]);
  foreach (@{$self->{sensors}}) {
    $_->{entPhySensorEntityName} = shift(@{$self->{entities}})->{entPhysicalName};
  }
  delete $self->{entities};
}

sub check {
  my $self = shift;
  foreach (@{$self->{sensors}}) {
    $_->check();
  }
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  foreach (@{$self->{sensors}}) {
    $_->dump();
  }
}


package Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  if ($self->{entPhySensorType} eq 'rpm') {
    bless $self, 'Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor::Fan';
  } elsif ($self->{entPhySensorType} eq 'celsius') {
    bless $self, 'Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor::Temperature';
  }
}

sub check {
  my $self = shift;
  if ($self->{entPhySensorOperStatus} ne 'ok') {
    $self->add_info(sprintf '%s has status %s\n',
        $self->{entity}->{entPhysicalName},
        $self->{entPhySensorOperStatus});
    if ($self->{entPhySensorOperStatus} eq 'nonoperational') {
      $self->add_critical();
    } else {
      $self->add_unknown();
    }
  } else {
    $self->add_info(sprintf "%s reports %s%s",
        $self->{entPhySensorEntityName},
        $self->{entPhySensorValue},
        $self->{entPhySensorUnitsDisplay}
    );
    #$self->add_ok();
  }
}


package Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor::Temperature;
our @ISA = qw(Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor);
use strict;

sub rename {
  my $self = shift;
}

sub check {
  my $self = shift;
  $self->SUPER::check();
  my $label = $self->{entPhySensorEntityName};
  $label =~ s/[Tt]emperature\s*@\s*(.*)/$1/;
  $self->add_perfdata(
    label => 'temp_'.$label,
    value => $self->{entPhySensorValue},
  );
}

package Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor::Fan;
our @ISA = qw(Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem::Sensor);
use strict;

sub check {
  my $self = shift;
  $self->SUPER::check();
  my $label = $self->{entPhySensorEntityName};
  $label =~ s/ RPM$//g;
  $label =~ s/Fan #(\d+)/$1/g;
  $self->add_perfdata(
    label => 'fan_'.$label,
    value => $self->{entPhySensorValue},
  );
}


package Classes::OSPF::Component::NeighborSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->establish_snmp_secondary_session();
  $self->get_snmp_tables('OSPF-MIB', [
    ['nbr', 'ospfNbrTable', 'Classes::OSPF::Component::NeighborSubsystem::Neighbor', , sub { my $o = shift; return $self->filter_name($o->{ospfNbrIpAddr}) && $self->filter_name2($o->{ospfNbrRtrId}) }],
  ]);
  if (! @{$self->{nbr}}) {
    $self->add_unknown("no neighbors found");
  }
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::ospf::neighbor::list/) {
    foreach (@{$self->{nbr}}) {
      printf "%s %s %s\n", $_->{name}, $_->{ospfNbrRtrId}, $_->{ospfNbrState};
    }
    $self->add_ok("have fun");
  } else {
    map { $_->check(); } @{$self->{nbr}};
  }
}

package Classes::OSPF::Component::NeighborSubsystem::Neighbor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
# Index: ospfNbrIpAddr, ospfNbrAddressLessIndex

sub finish {
  my $self = shift;
  $self->{name} = $self->{ospfNbrIpAddr} || $self->{ospfNbrAddressLessIndex}
}

sub check {
  my $self = shift;
  $self->add_info(sprintf "neighbor %s (Id %s) has status %s",
      $self->{name}, $self->{ospfNbrRtrId}, $self->{ospfNbrState});
  if ($self->{ospfNbrState} ne "full" && $self->{ospfNbrState} ne "twoWay") {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
}

# eventuell: warning, wenn sich die RouterId ändert
package Classes::OSPF;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::ospf::neighbor/) {
    $self->analyze_and_check_neighbor_subsystem("Classes::OSPF::Component::NeighborSubsystem");
  } else {
    $self->no_such_mode();
  }
}


package Classes::OSPF::Component::AreaSubsystem;
our @ISA = qw(Monitoring::GLPlugin::Item);
use strict;

package Classes::OSPF::Component::AreaSubsystem::Area;
our @ISA = qw(Monitoring::GLPlugin::TableItem);
use strict;
# Index: ospfAreaId

package Classes::OSPF::Component::HostSubsystem::Host;
our @ISA = qw(Monitoring::GLPlugin::TableItem);
use strict;
# Index: ospfHostIpAddress, ospfHostTOS

package Classes::OSPF::Component::InterfaceSubsystem::Interface;
our @ISA = qw(Monitoring::GLPlugin::TableItem);
use strict;
# Index: ospfIfIpAddress, ospfAddressLessIf




package Classes::BGP::Component::PeerSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

our $errorcodes = {
  0 => {
    0 => 'No Error',
  },
  1 => {
    0 => 'MESSAGE Header Error',
    1 => 'Connection Not Synchronized',
    2 => 'Bad Message Length',
    3 => 'Bad Message Type',
  },
  2 => {
    0 => 'OPEN Message Error',
    1 => 'Unsupported Version Number',
    2 => 'Bad Peer AS',
    3 => 'Bad BGP Identifier',
    4 => 'Unsupported Optional Parameter',
    5 => '[Deprecated => see Appendix A]',
    6 => 'Unacceptable Hold Time',
  },
  3 => {
    0 => 'UPDATE Message Error',
    1 => 'Malformed Attribute List',
    2 => 'Unrecognized Well-known Attribute',
    3 => 'Missing Well-known Attribute',
    4 => 'Attribute Flags Error',
    5 => 'Attribute Length Error',
    6 => 'Invalid ORIGIN Attribute',
    7 => '[Deprecated => see Appendix A]',
    8 => 'Invalid NEXT_HOP Attribute',
    9 => 'Optional Attribute Error',
   10 => 'Invalid Network Field',
   11 => 'Malformed AS_PATH',
  },
  4 => {
    0 => 'Hold Timer Expired',
  },
  5 => {
    0 => 'Finite State Machine Error',
  },
  6 => {
    0 => 'Cease',
    1 => 'Maximum Number of Prefixes Reached',
    2 => 'Administrative Shutdown',
    3 => 'Peer De-configured',
    4 => 'Administrative Reset',
    5 => 'Connection Rejected',
    6 => 'Other Configuration Change',
    7 => 'Connection Collision Resolution',
    8 => 'Out of Resources',
  },
};

sub init {
  my $self = shift;
  $self->{peers} = [];
  if ($self->mode =~ /device::bgp::peer::(list|count|watch)/) {
    $self->update_entry_cache(1, 'BGP4-MIB', 'bgpPeerTable', 'bgpPeerRemoteAddr');
  }
  foreach ($self->get_snmp_table_objects_with_cache(
      'BGP4-MIB', 'bgpPeerTable', 'bgpPeerRemoteAddr')) {
    if ($self->filter_name($_->{bgpPeerRemoteAddr})) {
      push(@{$self->{peers}},
          Classes::BGP::Component::PeerSubsystem::Peer->new(%{$_}));
    }
  }
}

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking bgp peers');
  if ($self->mode =~ /peer::list/) {
    foreach (sort {$a->{bgpPeerRemoteAddr} cmp $b->{bgpPeerRemoteAddr}} @{$self->{peers}}) {
      printf "%s\n", $_->{bgpPeerRemoteAddr};
      #$_->list();
    }
    $self->add_ok("have fun");
  } elsif ($self->mode =~ /peer::count/) {
    $self->add_info(sprintf "found %d peers", scalar(@{$self->{peers}}));
    $self->set_thresholds(warning => '1:', critical => '1:');
    $self->add_message($self->check_thresholds(scalar(@{$self->{peers}})));
    $self->add_perfdata(
        label => 'peers',
        value => scalar(@{$self->{peers}}),
    );
  } elsif ($self->mode =~ /peer::watch/) {
    # take a snapshot of the peer list. -> good baseline
    # warning if there appear peers, mitigate to ok
    # critical if warn/crit percent disappear
    $self->{numOfPeers} = scalar (@{$self->{peers}});
    $self->{peerNameList} = [map { $_->{bgpPeerRemoteAddr} } @{$self->{peers}}];
    $self->opts->override_opt('lookback', 3600) if ! $self->opts->lookback;
    if ($self->opts->reset) {
      my $statefile = $self->create_statefile(name => 'bgppeerlist', lastarray => 1);
      unlink $statefile if -f $statefile;
    }
    $self->valdiff({name => 'bgppeerlist', lastarray => 1},
        qw(peerNameList numOfPeers));
    my $problem = 0;
    if ($self->opts->warning || $self->opts->critical) {
      $self->set_thresholds(warning => $self->opts->warning,
          critical => $self->opts->critical);
      my $before = $self->{numOfPeers} - scalar(@{$self->{delta_found_peerNameList}}) + scalar(@{$self->{delta_lost_peerNameList}});
      # use own delta_numOfPeers, because the glplugin version treats
      # negative deltas as overflows
      $self->{delta_numOfPeers} = $self->{numOfPeers} - $before;
      if ($self->opts->units && $self->opts->units eq "%") {
        my $delta_pct = $before ? (($self->{delta_numOfPeers} / $before) * 100) : 0;
        $self->add_message($self->check_thresholds($delta_pct),
          sprintf "%.2f%% delta, before: %d, now: %d", $delta_pct, $before, $self->{numOfPeers});
        $problem = $self->check_thresholds($delta_pct);
      } else {
        $self->add_message($self->check_thresholds($self->{delta_numOfPeers}),
          sprintf "%d delta, before: %d, now: %d", $self->{delta_numOfPeers}, $before, $self->{numOfPeers});
        $problem = $self->check_thresholds($self->{delta_numOfPeers});
      }
      if (scalar(@{$self->{delta_found_peerNameList}}) > 0) {
        $self->add_ok(sprintf 'found: %s',
            join(", ", @{$self->{delta_found_peerNameList}}));
      }
      if (scalar(@{$self->{delta_lost_peerNameList}}) > 0) {
        $self->add_ok(sprintf 'lost: %s',
            join(", ", @{$self->{delta_lost_peerNameList}}));
      }
    } else {
      if (scalar(@{$self->{delta_found_peerNameList}}) > 0) {
        $self->add_warning(sprintf '%d new bgp peers (%s)',
            scalar(@{$self->{delta_found_peerNameList}}),
            join(", ", @{$self->{delta_found_peerNameList}}));
        $problem = 1;
      }
      if (scalar(@{$self->{delta_lost_peerNameList}}) > 0) {
        $self->add_critical(sprintf '%d bgp peers missing (%s)',
            scalar(@{$self->{delta_lost_peerNameList}}),
            join(", ", @{$self->{delta_lost_peerNameList}}));
        $problem = 2;
      }
      $self->add_ok(sprintf 'found %d bgp peers', scalar (@{$self->{peers}}));
    }
    if ($problem) { # relevant only for lookback=9999 and support contract customers
      $self->valdiff({name => 'bgppeerlist', lastarray => 1, freeze => 1},
          qw(peerNameList numOfPeers));
    } else {
      $self->valdiff({name => 'bgppeerlist', lastarray => 1, freeze => 2},
          qw(peerNameList numOfPeers));
    }
    $self->add_perfdata(
        label => 'num_peers',
        value => scalar (@{$self->{peers}}),
    );
  } else {
    if (scalar(@{$self->{peers}}) == 0) {
      $self->add_unknown('no peers');
      return;
    }
    # es gibt
    # kleine installation: 1 peer zu 1 as, evt 2. as als fallback
    # grosse installation: n peer zu 1 as, alternative routen zum provider
    #                      n peer zu m as, mehrere provider, mehrere alternativrouten
    # 1 ausfall on 4 peers zu as ist egal
    my $as_numbers = {};
    foreach (@{$self->{peers}}) {
      $_->check();
      if (! exists $as_numbers->{$_->{bgpPeerRemoteAs}}->{peers}) {
        $as_numbers->{$_->{bgpPeerRemoteAs}}->{peers} = [];
        $as_numbers->{$_->{bgpPeerRemoteAs}}->{availability} = 100;
      }
      push(@{$as_numbers->{$_->{bgpPeerRemoteAs}}->{peers}}, $_);
    }
    if ($self->opts->name2) {
      $self->clear_ok();
      $self->clear_critical();
      if ($self->opts->name2 eq "_ALL_") {
        $self->opts->override_opt("name2", join(",", keys %{$as_numbers}));
      }
      foreach my $as (split(",", $self->opts->name2)) {
        my $asname = "";
        if ($as =~ /(\d+)=(\w+)/) {
          $as = $1;
          $asname = $2;
        }
        if (exists $as_numbers->{$as}) {
          my $num_peers = scalar(@{$as_numbers->{$as}->{peers}});
          my $num_ok_peers = scalar(grep { $_->{bgpPeerFaulty} == 0 } @{$as_numbers->{$as}->{peers}});
          my $num_admdown_peers = scalar(grep { $_->{bgpPeerAdminStatus} eq "stop" } @{$as_numbers->{$as}->{peers}});
          $as_numbers->{$as}->{availability} = 100 * $num_ok_peers / $num_peers;
          $self->set_thresholds(warning => "100:", critical => "50:");
          $self->add_message($self->check_thresholds($as_numbers->{$as}->{availability}),
              sprintf "%d from %d connections to %s are up (%.2f%%%s)",
              $num_ok_peers, $num_peers, $asname ? $asname : "AS".$as,
              $as_numbers->{$as}->{availability},
              $num_admdown_peers ? sprintf(", but %d are admin down and counted as up!", $num_admdown_peers) : "");
        } else {
          $self->add_critical(sprintf 'found no peer for %s', $asname ? $asname : "AS".$as);
        }
      }
    }
    if ($self->opts->report eq "short") {
      $self->clear_ok();
      $self->add_ok('no problems') if ! $self->check_messages();
    }
  }
}


package Classes::BGP::Component::PeerSubsystem::Peer;
our @ISA = qw(Classes::BGP::Component::PeerSubsystem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {};
  foreach(keys %params) {
    $self->{$_} = $params{$_};
  }
  bless $self, $class;
  $self->{bgpPeerLastError} |= "00 00";
  my $errorcode = 0;
  my $subcode = 0;
  if (lc $self->{bgpPeerLastError} =~ /([0-9a-f]+)\s+([0-9a-f]+)/) {
    $errorcode = hex($1) * 1;
    $subcode = hex($2) * 1;
  }
  $self->{bgpPeerLastError} = $Classes::BGP::Component::PeerSubsystem::errorcodes->{$errorcode}->{$subcode};
  $self->{bgpPeerRemoteAsName} = "";
  $self->{bgpPeerRemoteAsImportant} = 0; # if named in --name2
  $self->{bgpPeerFaulty} = 0;
  my @parts = gmtime($self->{bgpPeerFsmEstablishedTime});
  $self->{bgpPeerFsmEstablishedTime} = sprintf ("%dd, %dh, %dm, %ds",@parts[7,2,1,0]);

  return $self;
}

sub check {
  my $self = shift;
  if ($self->opts->name2) {
    foreach my $as (split(",", $self->opts->name2)) {
      if ($as =~ /(\d+)=(\w+)/) {
        $as = $1;
        $self->{bgpPeerRemoteAsName} = ", ".$2;
      } else {
        $self->{bgpPeerRemoteAsName} = "";
      }
      if ($as eq "_ALL_" || $as == $self->{bgpPeerRemoteAs}) {
        $self->{bgpPeerRemoteAsImportant} = 1;
      }
    }
  } else {
    $self->{bgpPeerRemoteAsImportant} = 1;
  }
  if ($self->{bgpPeerState} eq "established") {
    $self->add_ok(sprintf "peer %s (AS%s) state is %s since %s",
        $self->{bgpPeerRemoteAddr},
        $self->{bgpPeerRemoteAs}.$self->{bgpPeerRemoteAsName},
        $self->{bgpPeerState},
        $self->{bgpPeerFsmEstablishedTime}
    );
  } elsif ($self->{bgpPeerAdminStatus} eq "stop") {
    # admin down is by default critical, but can be mitigated
    $self->add_message(
        defined $self->opts->mitigation() ? $self->opts->mitigation() :
            $self->{bgpPeerRemoteAsImportant} ? WARNING : OK,
        sprintf "peer %s (AS%s) state is %s (is admin down)",
        $self->{bgpPeerRemoteAddr},
        $self->{bgpPeerRemoteAs}.$self->{bgpPeerRemoteAsName},
        $self->{bgpPeerState}
    );
    $self->{bgpPeerFaulty} =
        defined $self->opts->mitigation() && $self->opts->mitigation() eq "ok" ? 0 :
        $self->{bgpPeerRemoteAsImportant} ? 1 : 0;
  } else {
    # bgpPeerLastError may be undef, at least under the following circumstances
    # bgpPeerRemoteAsName is "", bgpPeerAdminStatus is "start",
    # bgpPeerState is "active"
    $self->add_message($self->{bgpPeerRemoteAsImportant} ? CRITICAL : OK,
        sprintf "peer %s (AS%s) state is %s (last error: %s)",
        $self->{bgpPeerRemoteAddr},
        $self->{bgpPeerRemoteAs}.$self->{bgpPeerRemoteAsName},
        $self->{bgpPeerState},
        $self->{bgpPeerLastError}||"no error"
    );
    $self->{bgpPeerFaulty} = $self->{bgpPeerRemoteAsImportant} ? 1 : 0;
  }
}


package Classes::BGP;
our @ISA = qw(Classes::Device);
use strict;

package Classes::FCMGMT::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{sensor_subsystem} =
      Classes::FCMGMT::Component::SensorSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{sensor_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{sensor_subsystem}->dump();
}

package Classes::FCMGMT::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FCMGMT-MIB', [
      ['sensors', 'fcConnUnitSensorTable', 'Classes::FCMGMT::Component::SensorSubsystem::Sensor'],
  ]);
  foreach (@{$self->{sensors}}) {
    $_->{fcConnUnitSensorIndex} ||= $_->{flat_indices};
  }
}

package Classes::FCMGMT::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s sensor %s (%s) is %s (%s)',
      $self->{fcConnUnitSensorType},
      $self->{fcConnUnitSensorIndex},
      $self->{fcConnUnitSensorInfo},
      $self->{fcConnUnitSensorStatus},
      $self->{fcConnUnitSensorMessage});
  if ($self->{fcConnUnitSensorStatus} ne "ok") {
    $self->add_critical();
  } else {
    #$self->add_ok();
  }
}

package Classes::FCMGMT;
our @ISA = qw(Classes::Device);
use strict;

package Classes::FCEOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub overall_init {
  my $self = shift;
  $self->get_snmp_objects('FCEOS-MIB', (qw(
      fcEosSysOperStatus)));
}

sub init {
  my $self = shift;
  $self->{fru_subsystem} =
      Classes::FCEOS::Component::FruSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{fru_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  } else {
    if ($self->{fcEosSysOperStatus} eq "operational") {
      $self->clear_critical();
      $self->clear_warning();
    } elsif ($self->{fcEosSysOperStatus} eq "major-failure") {
      $self->add_critical("major device failure");
    } else {
      $self->add_warning($self->{fcEosSysOperStatus});
    }
  }
}

package Classes::FCEOS::Component::FruSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FCEOS-MIB', [
      ['frus', 'fcEosFruTable', 'Classes::FCEOS::Component::FruSubsystem::Fcu'],
  ]);
}

package Classes::FCEOS::Component::FruSubsystem::Fcu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s fru (pos %s) is %s',
      $self->{fcEosFruCode},
      $self->{fcEosFruPosition},
      $self->{fcEosFruStatus});
  if ($self->{fcEosFruStatus} eq "failed") {
    $self->add_critical();
  } else {
    #$self->add_ok();
  }
}

package Classes::FCEOS;
our @ISA = qw(Classes::Device);
use strict;

package Classes::UCDMIB::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('UCD-SNMP-MIB', (qw(
      memTotalSwap memAvailSwap memTotalReal memAvailReal memTotalFree)));
  # https://kc.mcafee.com/corporate/index?page=content&id=KB73175
  $self->{mem_usage} = ($self->{memTotalReal} - $self->{memTotalFree}) /
      $self->{memTotalReal} * 100;
  $self->{mem_usage} = $self->{memAvailReal} * 100 / $self->{memTotalReal};
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{mem_usage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{mem_usage});
    $self->set_thresholds(warning => 80,
        critical => 90);
    $self->add_message($self->check_thresholds($self->{mem_usage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{mem_usage},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

package Classes::UCDMIB::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('UCD-SNMP-MIB', (qw(
      ssCpuUser ssCpuSystem ssCpuIdle ssCpuRawUser ssCpuRawSystem ssCpuRawIdle ssCpuRawNice)));
  $self->valdiff({name => 'cpu'}, qw(ssCpuRawUser ssCpuRawSystem ssCpuRawIdle ssCpuRawNice));
  my $cpu_total = $self->{delta_ssCpuRawUser} + $self->{delta_ssCpuRawSystem} +
      $self->{delta_ssCpuRawIdle} + $self->{delta_ssCpuRawNice};
  if ($cpu_total == 0) {
    $self->{cpu_usage} = 0;
  } else {
    $self->{cpu_usage} = (100 - ($self->{delta_ssCpuRawIdle} / $cpu_total) * 100);
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{cpu_usage});
  $self->set_thresholds(warning => 50, critical => 90);
  $self->add_message($self->check_thresholds($self->{cpu_usage}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{cpu_usage},
      uom => '%',
  );
}

sub unix_init {
  my $self = shift;
  my %params = @_;
  my $type = 0;
  $self->get_snmp_tables('UCD-SNMP-MIB', [
      ['loads', 'laTable', 'Classes::UCDMIB::Component::CpuSubsystem::Load'],
  ]);
}

sub unix_check {
  my $self = shift;
  $self->add_info('checking loads');
  foreach (@{$self->{loads}}) {
    $_->check();
  }
}

sub unix_dump {
  my $self = shift;
  foreach (@{$self->{loads}}) {
    $_->dump();
  }
}


package Classes::UCDMIB::Component::CpuSubsystem::Load;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info(sprintf '%s is %.2f', lc $self->{laNames}, $self->{laLoadFloat});
  $self->set_thresholds(warning => $self->{laConfig},
      critical => $self->{laConfig});
  $self->add_message($self->check_thresholds($self->{laLoadFloat}));
  $self->add_perfdata(
      label => lc $self->{laNames},
      value => $self->{laLoadFloat},
  );
}

package Classes::UCDMIB;
our @ISA = qw(Classes::Device);
use strict;

package Classes::F5::F5BIGIP::Component::LTMSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

{
  our $max_l4_connections = 10000000;
}

sub max_l4_connections : lvalue {
  my $self = shift;
  $Classes::F5::F5BIGIP::Component::LTMSubsystem::max_l4_connections;
}

sub new {
  my $class = shift;
  my %params = @_;
  my $self = {
    sysProductVersion => $params{sysProductVersion},
    sysPlatformInfoMarketingName => $params{sysPlatformInfoMarketingName},
  };
  if ($self->{sysProductVersion} =~ /^4/) {
    bless $self, "Classes::F5::F5BIGIP::Component::LTMSubsystem4";
    $self->debug("use Classes::F5::F5BIGIP::Component::LTMSubsystem4");
  } else {
    bless $self, "Classes::F5::F5BIGIP::Component::LTMSubsystem9";
    $self->debug("use Classes::F5::F5BIGIP::Component::LTMSubsystem9");
  }
  # tables can be huge
  $self->mult_snmp_max_msg_size(10);
  $self->set_max_l4_connections();
  $self->init();
  return $self;
}

sub set_max_l4_connections {
  my $self = shift;
  if ($self->{sysPlatformInfoMarketingName} && 
      $self->{sysPlatformInfoMarketingName} =~ /BIG-IP\s*(\d+)/i) {
    if ($1 =~ /^(1500)$/) {
      $self->max_l4_connections() = 1500000;
    } elsif ($1 =~ /^(1600)$/) {
      $self->max_l4_connections() = 3000000;
    } elsif ($1 =~ /^(2000|2200)$/) {
      $self->max_l4_connections() = 5000000;
    } elsif ($1 =~ /^(3400)$/) {
      $self->max_l4_connections() = 4000000;
    } elsif ($1 =~ /^(3600|8800|8400)$/) {
      $self->max_l4_connections() = 8000000;
    } elsif ($1 =~ /^(4000|4200)$/) {
      $self->max_l4_connections() = 10000000;
    } elsif ($1 =~ /^(8900|8950)$/) {
      $self->max_l4_connections() = 12000000;
    } elsif ($1 =~ /^(5000|5050|5200|5250|7000|7050|7200|7250|11050)$/) {
      $self->max_l4_connections() = 24000000;
    } elsif ($1 =~ /^(10000|10050|10200|10250)$/) {
      $self->max_l4_connections() = 36000000;
    } elsif ($1 =~ /^(10350|12250)$/) {
      $self->max_l4_connections() = 80000000;
    } elsif ($1 =~ /^(11000)$/) {
      $self->max_l4_connections() = 30000000;
    }
  } elsif ($self->{sysPlatformInfoMarketingName} && 
      $self->{sysPlatformInfoMarketingName} =~ /Viprion\s*(\d+)/i) {
    if ($1 =~ /^(2100)$/) {
      $self->max_l4_connections() = 12000000;
    } elsif ($1 =~ /^(2150)$/) {
      $self->max_l4_connections() = 24000000;
    } elsif ($1 =~ /^(2200|2250|2400)$/) {
      $self->max_l4_connections() = 48000000;
    } elsif ($1 =~ /^(4300)$/) {
      $self->max_l4_connections() = 36000000;
    } elsif ($1 =~ /^(4340|4800)$/) {
      $self->max_l4_connections() = 72000000;
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking ltm pools');
  if (scalar(@{$self->{pools}}) == 0) {
    $self->add_unknown('no pools');
    return;
  }
  if ($self->mode =~ /pool::list/) {
    foreach (sort {$a->{ltmPoolName} cmp $b->{ltmPoolName}} @{$self->{pools}}) {
      printf "%s\n", $_->{ltmPoolName};
      #$_->list();
    }
  } else {
    foreach (@{$self->{pools}}) {
      $_->check();
    }
  }
}


package Classes::F5::F5BIGIP::Component::LTMSubsystem9;
our @ISA = qw(Classes::F5::F5BIGIP::Component::LTMSubsystem Monitoring::GLPlugin::SNMP::TableItem);
use strict;

#
# A node is an ip address (may belong to more than one pool)
# A pool member is an ip:port combination
#

sub init {
  my $self = shift;
  # ! merge ltmPoolStatus, ltmPoolMemberStatus, bec. ltmPoolAvailabilityState is deprecated
  if ($self->mode =~ /pool::list/) {
    $self->update_entry_cache(1, 'F5-BIGIP-LOCAL-MIB', 'ltmPoolStatusTable', 'ltmPoolStatusName');
    $self->update_entry_cache(1, 'F5-BIGIP-LOCAL-MIB', 'ltmPoolTable', 'ltmPoolName');
    $self->update_entry_cache(1, 'F5-BIGIP-LOCAL-MIB', 'ltmPoolMbrStatusTable', 'ltmPoolMbrStatusPoolName');
    $self->update_entry_cache(1, 'F5-BIGIP-LOCAL-MIB', 'ltmPoolMemberTable', 'ltmPoolMemberPoolName');
    $self->update_entry_cache(1, 'F5-BIGIP-LOCAL-MIB', 'ltmPoolStatTable', 'ltmPoolStatName');
  }
  my @auxpools = ();
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolStatusTable', 'ltmPoolStatusName')) {
    push(@auxpools, $_);
  }
  if (! grep { $self->filter_name($_->{ltmPoolStatusName}) } @auxpools) {
    #$self->add_unknown("did not find any pools");
    $self->{pools} = [];
    return;
  }
  my @auxstats = ();
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolStatTable', 'ltmPoolStatName')) {
    push(@auxstats, $_) if $self->filter_name($_->{ltmPoolStatName});
  }
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolTable', 'ltmPoolName')) {
    foreach my $auxpool (@auxpools) {
      if ($_->{ltmPoolName} eq $auxpool->{ltmPoolStatusName}) {
        foreach my $key (keys %{$auxpool}) {
          $_->{$key} = $auxpool->{$key};
        }
      }
    }
    foreach my $auxstat (@auxstats) {
      if ($_->{ltmPoolName} eq $auxstat->{ltmPoolStatName}) {
        foreach my $key (keys %{$auxstat}) {
          $_->{$key} = $auxstat->{$key};
        }
      }
    }
    push(@{$self->{pools}},
        Classes::F5::F5BIGIP::Component::LTMSubsystem9::LTMPool->new(%{$_}));
  }
  my @auxpoolmbrstatus = ();
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolMbrStatusTable', 'ltmPoolMbrStatusPoolName')) {
    next if ! defined $_->{ltmPoolMbrStatusPoolName};
    $_->{ltmPoolMbrStatusAddr} = $self->unhex_ip($_->{ltmPoolMbrStatusAddr});
    push(@auxpoolmbrstatus, $_);
  }
  my @auxpoolmemberstat = ();
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolMemberStatTable', 'ltmPoolMemberStatPoolName')) {
    $_->{ltmPoolMemberStatAddr} = $self->unhex_ip($_->{ltmPoolMemberStatAddr});
    push(@auxpoolmemberstat, $_);
    # ltmPoolMemberStatAddr is deprecated, use ltmPoolMemberStatNodeName
  }
  foreach ($self->get_snmp_table_objects_with_cache(
      'F5-BIGIP-LOCAL-MIB', 'ltmPoolMemberTable', 'ltmPoolMemberPoolName')) {
    $_->{ltmPoolMemberAddr} = $self->unhex_ip($_->{ltmPoolMemberAddr});
    foreach my $auxmbr (@auxpoolmbrstatus) {
      if ($_->{ltmPoolMemberPoolName} eq $auxmbr->{ltmPoolMbrStatusPoolName} &&
          $_->{ltmPoolMemberPort} eq $auxmbr->{ltmPoolMbrStatusPort} &&
          $_->{ltmPoolMemberAddrType} eq $auxmbr->{ltmPoolMbrStatusAddrType} &&
          $_->{ltmPoolMemberAddr} eq $auxmbr->{ltmPoolMbrStatusAddr}) {
        foreach my $key (keys %{$auxmbr}) {
          next if $key =~ /.*indices$/;
          $_->{$key} = $auxmbr->{$key};
        }
      }
    }
    foreach my $auxmember (@auxpoolmemberstat) {
      if ($_->{ltmPoolMemberPoolName} eq $auxmember->{ltmPoolMemberStatPoolName} &&
          $_->{ltmPoolMemberPort} eq $auxmember->{ltmPoolMemberStatPort} &&
          $_->{ltmPoolMemberNodeName} eq $auxmember->{ltmPoolMemberStatNodeName}) {
        foreach my $key (keys %{$auxmember}) {
          next if $key =~ /.*indices$/;
          $_->{$key} = $auxmember->{$key};
        }
      }
    }
    push(@{$self->{poolmembers}},
        Classes::F5::F5BIGIP::Component::LTMSubsystem9::LTMPoolMember->new(%{$_}));
  }
  # ltmPoolMemberNodeName may be the same as ltmPoolMemberAddr
  # there is a chance to learn the actual hostname via ltmNodeAddrStatusName
  # so if there ia a member with name==addr, we get the addrstatus table
  my $need_name_from_addr = 0;
  foreach my $poolmember (@{$self->{poolmembers}}) {
    if ($poolmember->{ltmPoolMemberNodeName} eq $poolmember->{ltmPoolMemberAddr}) {
      $need_name_from_addr = 1;
    }
  }
  if ($need_name_from_addr) {
    my @auxnodeaddrstatus = ();
    foreach ($self->get_snmp_table_objects(
        'F5-BIGIP-LOCAL-MIB', 'ltmNodeAddrStatusTable')) {
      $_->{ltmNodeAddrStatusAddr} = $self->unhex_ip($_->{ltmNodeAddrStatusAddr});
      push(@auxnodeaddrstatus, $_);
    }
    foreach my $poolmember (@{$self->{poolmembers}}) {
      foreach my $auxaddr (@auxnodeaddrstatus) {
        if ($poolmember->{ltmPoolMemberAddrType} eq $auxaddr->{ltmNodeAddrStatusAddrType} &&
            $poolmember->{ltmPoolMemberAddr} eq $auxaddr->{ltmNodeAddrStatusAddr}) {
          $poolmember->{ltmNodeAddrStatusName} = $auxaddr->{ltmNodeAddrStatusName};
          last;
          # needed later, if ltmNodeAddrStatusName is an ip-address. LTMPoolMember::finish
        }
      }
    }
  } else {
    foreach my $poolmember (@{$self->{poolmembers}}) {
      # because later we use ltmNodeAddrStatusName
      $poolmember->{ltmNodeAddrStatusName} = $poolmember->{ltmPoolMemberNodeName};
      my $x = 1;
    }
  }
  foreach my $poolmember (@{$self->{poolmembers}}) {
    $poolmember->rename();
  }
  $self->assign_members_to_pools();
}

sub assign_members_to_pools {
  my $self = shift;
  foreach my $pool (@{$self->{pools}}) {
    foreach my $poolmember (@{$self->{poolmembers}}) {
      if ($poolmember->{ltmPoolMemberPoolName} eq $pool->{ltmPoolName}) {
        $poolmember->{ltmPoolMonitorRule} = $pool->{ltmPoolMonitorRule};
        push(@{$pool->{members}}, $poolmember);
      }
    }
    if (! defined $pool->{ltmPoolMemberCnt}) {
      $pool->{ltmPoolMemberCnt} = scalar(@{$pool->{members}}) ;
      $self->debug("calculate ltmPoolMemberCnt");
    }
    $pool->{completeness} = $pool->{ltmPoolMemberCnt} ?
        $pool->{ltmPoolActiveMemberCnt} / $pool->{ltmPoolMemberCnt} * 100
        : 0;
  }
}


package Classes::F5::F5BIGIP::Component::LTMSubsystem9::LTMPool;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub finish {
  my $self = shift;
  $self->{ltmPoolMemberMonitorRule} ||= $self->{ltmPoolMonitorRule};
  $self->{members} = [];
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::lb::pool::comple/) {
    my $pool_info = sprintf "pool %s is %s, avail state is %s, active members: %d of %d, connections: %d",
        $self->{ltmPoolName},
        $self->{ltmPoolStatusEnabledState}, $self->{ltmPoolStatusAvailState},
        $self->{ltmPoolActiveMemberCnt}, $self->{ltmPoolMemberCnt}, $self->{ltmPoolStatServerCurConns};
    $self->add_info($pool_info);
    if ($self->{ltmPoolActiveMemberCnt} == 1) {
      # only one member left = no more redundancy!!
      $self->set_thresholds(
          metric => sprintf('pool_%s_completeness', $self->{ltmPoolName}),
          warning => "100:", critical => "51:");
    } else {
      $self->set_thresholds(
          metric => sprintf('pool_%s_completeness', $self->{ltmPoolName}),
          warning => "51:", critical => "26:");
    }
    $self->add_message($self->check_thresholds(
        metric => sprintf('pool_%s_completeness', $self->{ltmPoolName}),
        value => $self->{completeness}));
    if ($self->{ltmPoolMinActiveMembers} > 0 &&
        $self->{ltmPoolActiveMemberCnt} < $self->{ltmPoolMinActiveMembers}) {
      $self->annotate_info(sprintf("not enough active members (%d, min is %d)",
              $self->{ltmPoolName}, $self->{ltmPoolActiveMemberCnt},
              $self->{ltmPoolMinActiveMembers}));
      $self->add_message(defined $self->opts->mitigation() ? $self->opts->mitigation() : CRITICAL);
    }
    if ($self->check_messages() || $self->mode  =~ /device::lb::pool::co.*tions/) {
      foreach my $member (@{$self->{members}}) {
        $member->check();
      }
    }
    $self->add_perfdata(
        label => sprintf('pool_%s_completeness', $self->{ltmPoolName}),
        value => $self->{completeness},
        uom => '%',
    );
    $self->add_perfdata(
        label => sprintf('pool_%s_servercurconns', $self->{ltmPoolName}),
        value => $self->{ltmPoolStatServerCurConns},
        warning => undef, critical => undef,
    );
    if ($self->opts->report eq "html") {
      printf "%s - %s%s\n", $self->status_code($self->check_messages()), $pool_info, $self->perfdata_string() ? " | ".$self->perfdata_string() : "";
      $self->suppress_messages();
      $self->draw_html_table();
    }
  } elsif ($self->mode =~ /device::lb::pool::connections/) {
    foreach my $member (@{$self->{members}}) {
      $member->check();
    }
  }
}

sub draw_html_table {
  my $self = shift;
  if ($self->mode =~ /device::lb::pool::comple/) {
    my @headers = qw(Node Port Enabled Avail Reason);
    my @columns = qw(ltmPoolMemberNodeName ltmPoolMemberPort ltmPoolMbrStatusEnabledState ltmPoolMbrStatusAvailState ltmPoolMbrStatusDetailReason);
    if ($self->mode =~ /device::lb::pool::complections/) {
      push(@headers, "Connections");
      push(@headers, "ConnPct");
      push(@columns, "ltmPoolMemberStatServerCurConns");
      push(@columns, "ltmPoolMemberStatServerPctConns");
      foreach my $member (@{$self->{members}}) {
        $member->{ltmPoolMemberStatServerPctConns} = sprintf "%.5f", $member->{ltmPoolMemberStatServerPctConns};
      }
    }
    printf "<table style=\"border-collapse:collapse; border: 1px solid black;\">";
    printf "<tr>";
    foreach (@headers) {
      printf "<th style=\"text-align: left; padding-left: 4px; padding-right: 6px;\">%s</th>", $_;
    }
    printf "</tr>";
    foreach (sort {$a->{ltmPoolMemberNodeName} cmp $b->{ltmPoolMemberNodeName}} @{$self->{members}}) {
      printf "<tr>";
      printf "<tr style=\"border: 1px solid black;\">";
      foreach my $attr (@columns) {
        if ($_->{ltmPoolMbrStatusEnabledState} eq "enabled") {
          if ($_->{ltmPoolMbrStatusAvailState} eq "green") {
            printf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px; background-color: #33ff00;\">%s</td>", $_->{$attr};
          } else {
            printf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px; background-color: #f83838;\">%s</td>", $_->{$attr};
          }
        } else {
          printf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px; background-color: #acacac;\">%s</td>", $_->{$attr};
        }
      }
      printf "</tr>";
    }
    printf "</table>\n";
    printf "<!--\nASCII_NOTIFICATION_START\n";
    foreach (@headers) {
      printf "%20s", $_;
    }
    printf "\n";
    foreach (sort {$a->{ltmPoolMemberNodeName} cmp $b->{ltmPoolMemberNodeName}} @{$self->{members}}) {
      foreach my $attr (@columns) {
        printf "%20s", $_->{$attr};
      }
      printf "\n";
    }
    printf "ASCII_NOTIFICATION_END\n-->\n";
  } elsif ($self->mode =~ /device::lb::pool::complections/) {
  }
}

package Classes::F5::F5BIGIP::Component::LTMSubsystem9::LTMPoolMember;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub max_l4_connections {
  my $self = shift;
  $Classes::F5::F5BIGIP::Component::LTMSubsystem::max_l4_connections;
}

sub finish {
  my $self = shift;
  if ($self->mode =~ /device::lb::pool::comple/) {
    $self->{ltmPoolMemberNodeName} ||= $self->{ltmPoolMemberAddr};
  }
  if (! exists $self->{ltmPoolMemberStatPoolName}) {
    # if ltmPoolMbrStatusDetailReason: Forced down
    #    ltmPoolMbrStatusEnabledState: disabled
    # then we have no ltmPoolMemberStat*
    $self->{ltmPoolMemberStatServerCurConns} = 0;
  }
  if ($self->mode =~ /device::lb::pool::co.*ctions/) {
    # in rare cases we suddenly get noSuchInstance for ltmPoolMemberConnLimit
    # looks like shortly before a member goes down, all attributes get noSuchInstance
    #  except ltmPoolMemberStatAddr, ltmPoolMemberAddr,ltmPoolMemberStatusAddr
    # after a while, the member appears again, but Forced down and without Stats (see above)
    $self->protect_value($self->{ltmPoolMemberAddr},
        'ltmPoolMemberConnLimit', 'positive');
    $self->protect_value($self->{ltmPoolMemberAddr},
        'ltmPoolMemberStatServerCurConns', 'positive');
    if (! $self->{ltmPoolMemberConnLimit}) {
      $self->{ltmPoolMemberConnLimit} = $self->max_l4_connections();
    }
    $self->{ltmPoolMemberStatServerPctConns} = 
        100 * $self->{ltmPoolMemberStatServerCurConns} /
        $self->{ltmPoolMemberConnLimit};
  }
}

sub rename {
  my $self = shift;
  if ($self->{ltmPoolMemberNodeName} eq $self->{ltmPoolMemberAddr} &&
      $self->{ltmNodeAddrStatusName}) {
    $self->{ltmPoolMemberNodeName} = $self->{ltmNodeAddrStatusName};
  }
}

sub check {
  my $self = shift;
  if ($self->mode =~ /device::lb::pool::comple.*/) {
    if ($self->{ltmPoolMbrStatusEnabledState} eq "enabled") {
      if ($self->{ltmPoolMbrStatusAvailState} ne "green") {
        # info only, because it would ruin thresholds in the pool
        $self->add_ok(sprintf 
            "member %s:%s is %s/%s (%s)",
            $self->{ltmPoolMemberNodeName},
            $self->{ltmPoolMemberPort},
            $self->{ltmPoolMemberMonitorState},
            $self->{ltmPoolMbrStatusAvailState},
            $self->{ltmPoolMbrStatusDetailReason});
      }
    }
  }
  if ($self->mode =~ /device::lb::pool::co.*ctions/) {
    my $label = $self->{ltmPoolMemberNodeName}.'_'.$self->{ltmPoolMemberPort};
    $self->set_thresholds(metric => $label.'_connections_pct', warning => "85", critical => "95");
    $self->add_info(sprintf "member %s:%s has %d connections (from max %dM)",
        $self->{ltmPoolMemberNodeName},
        $self->{ltmPoolMemberPort},
        $self->{ltmPoolMemberStatServerCurConns},
        $self->{ltmPoolMemberConnLimit} / 1000000);
    $self->add_message($self->check_thresholds(metric => $label.'_connections_pct', value => $self->{ltmPoolMemberStatServerPctConns}));
    $self->add_perfdata(
        label => $label.'_connections_pct',
        value => $self->{ltmPoolMemberStatServerPctConns},
        uom => '%',
    );
    $self->add_perfdata(
        label => $label.'_connections',
        value => $self->{ltmPoolMemberStatServerCurConns},
        warning => undef, critical => undef,
    );
  }
}


package Classes::F5::F5BIGIP::Component::LTMSubsystem4;
our @ISA = qw(Classes::F5::F5BIGIP::Component::LTMSubsystem Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub init {
  my $self = shift;
  foreach ($self->get_snmp_table_objects(
      'LOAD-BAL-SYSTEM-MIB', 'poolTable')) {
    if ($self->filter_name($_->{poolName})) {
      push(@{$self->{pools}},
          Classes::F5::F5BIGIP::Component::LTMSubsystem4::LTMPool->new(%{$_}));
    }
  }
  foreach ($self->get_snmp_table_objects(
      'LOAD-BAL-SYSTEM-MIB', 'poolMemberTable')) {
    if ($self->filter_name($_->{poolMemberPoolName})) {
      push(@{$self->{poolmembers}},
          Classes::F5::F5BIGIP::Component::LTMSubsystem4::LTMPoolMember->new(%{$_}));
    }
  }
  $self->assign_members_to_pools();
}

sub assign_members_to_pools {
  my $self = shift;
  foreach my $pool (@{$self->{pools}}) {
    foreach my $poolmember (@{$self->{poolmembers}}) {
      if ($poolmember->{poolMemberPoolName} eq $pool->{poolName}) {
        push(@{$pool->{members}}, $poolmember);
      }
    }
    if (! defined $pool->{poolMemberQty}) {
      $pool->{poolMemberQty} = scalar(@{$pool->{members}}) ;
      $self->debug("calculate poolMemberQty");
    }
    $pool->{completeness} = $pool->{poolMemberQty} ?
        $pool->{poolActiveMemberCount} / $pool->{poolMemberQty} * 100
        : 0;
  }
}


package Classes::F5::F5BIGIP::Component::LTMSubsystem4::LTMPool;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub finish {
  my $self = shift;
  $self->{members} = [];
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'pool %s active members: %d of %d', $self->{poolName},
      $self->{poolActiveMemberCount},
      $self->{poolMemberQty});
  if ($self->{poolActiveMemberCount} == 1) {
    # only one member left = no more redundancy!!
    $self->set_thresholds(warning => "100:", critical => "51:");
  } else {
    $self->set_thresholds(warning => "51:", critical => "26:");
  }
  $self->add_message($self->check_thresholds($self->{completeness}));
  if ($self->{poolMinActiveMembers} > 0 &&
      $self->{poolActiveMemberCount} < $self->{poolMinActiveMembers}) {
    $self->add_nagios(
        defined $self->opts->mitigation() ? $self->opts->mitigation() : CRITICAL,
        sprintf("pool %s has not enough active members (%d, min is %d)", 
            $self->{poolName}, $self->{poolActiveMemberCount}, 
            $self->{poolMinActiveMembers})
    );
  }
  $self->add_perfdata(
      label => sprintf('pool_%s_completeness', $self->{poolName}),
      value => $self->{completeness},
      uom => '%',
      warning => $self->{warning},
      critical => $self->{critical},
  );
}


package Classes::F5::F5BIGIP::Component::LTMSubsystem4::LTMPoolMember;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

package Classes::F5::F5BIGIP::Component::DiskSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('F5-BIGIP-SYSTEM-MIB', [
      ['disks', 'sysPhysicalDiskTable', 'Classes::F5::F5BIGIP::Component::DiskSubsystem::Disk'],
  ]);
}

package Classes::F5::F5BIGIP::Component::DiskSubsystem::Disk;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'disk %s is %s',
      $self->{sysPhysicalDiskName},
      $self->{sysPhysicalDiskArrayStatus});
  if ($self->{sysPhysicalDiskArrayStatus} eq 'failed' && $self->{sysPhysicalDiskIsArrayMember} eq 'false') {
    $self->add_critical();
  } elsif ($self->{sysPhysicalDiskArrayStatus} eq 'failed' && $self->{sysPhysicalDiskIsArrayMember} eq 'true') {
    $self->add_warning();
  }
  # diskname CF* usually has status unknown 
}

package Classes::F5::F5BIGIP::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('F5-BIGIP-SYSTEM-MIB', (qw(
      sysStatMemoryTotal sysStatMemoryUsed sysHostMemoryTotal sysHostMemoryUsed)));
  $self->{stat_mem_usage} = ($self->{sysStatMemoryUsed} / $self->{sysStatMemoryTotal}) * 100;
  $self->{host_mem_usage} = ($self->{sysHostMemoryUsed} / $self->{sysHostMemoryTotal}) * 100;
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'tmm memory usage is %.2f%%',
      $self->{stat_mem_usage});
  $self->set_thresholds(warning => 80, critical => 90, metric => 'tmm_usage');
  $self->add_message($self->check_thresholds(metric => 'tmm_usage', value => $self->{stat_mem_usage}));
  $self->add_perfdata(
      label => 'tmm_usage',
      value => $self->{stat_mem_usage},
      uom => '%',
  );
  $self->add_info(sprintf 'host memory usage is %.2f%%',
      $self->{host_mem_usage});
  $self->set_thresholds(warning => 100, critical => 100, metric => 'host_usage');
  $self->add_message($self->check_thresholds(metric => 'host_usage', value => $self->{host_mem_usage}));
  $self->add_perfdata(
      label => 'host_usage',
      value => $self->{host_mem_usage},
      uom => '%',
  );
}

package Classes::F5::F5BIGIP::Component::PowersupplySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('F5-BIGIP-SYSTEM-MIB', [
      ['powersupplies', 'sysChassisPowerSupplyTable', 'Classes::F5::F5BIGIP::Component::PowersupplySubsystem::Powersupply'],
  ]);
}

package Classes::F5::F5BIGIP::Component::PowersupplySubsystem::Powersupply;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'chassis powersupply %d is %s',
      $self->{sysChassisPowerSupplyIndex},
      $self->{sysChassisPowerSupplyStatus});
  if ($self->{sysChassisPowerSupplyStatus} eq 'notpresent') {
  } else {
    if ($self->{sysChassisPowerSupplyStatus} ne 'good') {
      $self->add_critical();
    }
  }
}

package Classes::F5::F5BIGIP::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('F5-BIGIP-SYSTEM-MIB', [
      ['temperatures', 'sysChassisTempTable', 'Classes::F5::F5BIGIP::Component::TemperatureSubsystem::Temperature'],
  ]);
}

package Classes::F5::F5BIGIP::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'chassis temperature %d is %sC',
      $self->{sysChassisTempIndex},
      $self->{sysChassisTempTemperature});
  $self->add_perfdata(
      label => sprintf('temp_%s', $self->{sysChassisTempIndex}),
      value => $self->{sysChassisTempTemperature},
  );
}

package Classes::F5::F5BIGIP::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub new {
  my $class = shift;
  my $self = {};
  bless $self, $class;
  if ($self->mode =~ /load/) {
    $self->overall_init();
  } else {
    $self->init();
  }
  return $self;
}

sub overall_init {
  my $self = shift;
  $self->get_snmp_objects('F5-BIGIP-SYSTEM-MIB', (qw(
      sysStatTmTotalCycles sysStatTmIdleCycles sysStatTmSleepCycles)));
  $self->valdiff({name => 'cpu'}, qw(sysStatTmTotalCycles sysStatTmIdleCycles sysStatTmSleepCycles ));
  my $delta_used_cycles = $self->{delta_sysStatTmTotalCycles} -
     ($self->{delta_sysStatTmIdleCycles} + $self->{delta_sysStatTmSleepCycles});
  $self->{cpu_usage} =  $self->{delta_sysStatTmTotalCycles} ?
      (($delta_used_cycles / $self->{delta_sysStatTmTotalCycles}) * 100) : 0;
}

sub init {
  my $self = shift;
  $self->get_snmp_tables('F5-BIGIP-SYSTEM-MIB', [
      ['cpus', 'sysCpuTable', 'Classes::F5::F5BIGIP::Component::CpuSubsystem::Cpu'],
  ]);
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  if ($self->mode =~ /load/) {
    $self->add_info(sprintf 'tmm cpu usage is %.2f%%',
        $self->{cpu_usage});
    $self->set_thresholds(warning => 80, critical => 90);
    $self->add_message($self->check_thresholds($self->{cpu_usage}));
    $self->add_perfdata(
        label => 'cpu_tmm_usage',
        value => $self->{cpu_usage},
        uom => '%',
    );
    return;
  }
  foreach (@{$self->{cpus}}) {
    $_->check();
  }
}


package Classes::F5::F5BIGIP::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %d has %dC (%drpm)',
      $self->{sysCpuIndex},
      $self->{sysCpuTemperature},
      $self->{sysCpuFanSpeed});
  $self->add_perfdata(
      label => sprintf('temp_c%s', $self->{sysCpuIndex}),
      value => $self->{sysCpuTemperature},
      thresholds => 0,
  );
  $self->add_perfdata(
      label => sprintf('fan_c%s', $self->{sysCpuIndex}),
      value => $self->{sysCpuFanSpeed},
      thresholds => 0,
  );
}

package Classes::F5::F5BIGIP::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('F5-BIGIP-SYSTEM-MIB', [
      ['fans', 'sysChassisFanTable', 'Classes::F5::F5BIGIP::Component::FanSubsystem::Fan'],
  ]);
}

package Classes::F5::F5BIGIP::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'chassis fan %d is %s (%drpm)',
      $self->{sysChassisFanIndex},
      $self->{sysChassisFanStatus},
      $self->{sysChassisFanSpeed});
  if ($self->{sysChassisFanStatus} eq 'notpresent') {
  } else {
    if ($self->{sysChassisFanStatus} ne 'good') {
      $self->add_critical();
    }
    $self->add_perfdata(
        label => sprintf('fan_%s', $self->{sysChassisFanIndex}),
        value => $self->{sysChassisFanSpeed},
    );
  }
}

package Classes::F5::F5BIGIP::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub new {
  my $class = shift;
  my $self = {};
  bless $self, $class;
  $self->init();
  return $self;
}

sub init {
  my $self = shift;
  $self->{cpu_subsystem} =
      Classes::F5::F5BIGIP::Component::CpuSubsystem->new();
  $self->{fan_subsystem} =
      Classes::F5::F5BIGIP::Component::FanSubsystem->new();
  $self->{temperature_subsystem} =
      Classes::F5::F5BIGIP::Component::TemperatureSubsystem->new();
  $self->{powersupply_subsystem} = 
      Classes::F5::F5BIGIP::Component::PowersupplySubsystem->new();
  $self->{disk_subsystem} = 
      Classes::F5::F5BIGIP::Component::DiskSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{cpu_subsystem}->check();
  $self->{fan_subsystem}->check();
  $self->{temperature_subsystem}->check();
  $self->{powersupply_subsystem}->check();
  $self->{disk_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{cpu_subsystem}->dump();
  $self->{fan_subsystem}->dump();
  $self->{temperature_subsystem}->dump();
  $self->{powersupply_subsystem}->dump();
  $self->{disk_subsystem}->dump();
}

package Classes::F5::F5BIGIP;
our @ISA = qw(Classes::F5);
use strict;

sub init {
  my $self = shift;
  # gets 11.* and 9.*
  $self->{sysProductVersion} = $self->get_snmp_object('F5-BIGIP-SYSTEM-MIB', 'sysProductVersion');
  $self->{sysPlatformInfoMarketingName} = $self->get_snmp_object('F5-BIGIP-SYSTEM-MIB', 'sysPlatformInfoMarketingName');
  if (! defined $self->{sysProductVersion} ||
      $self->{sysProductVersion} !~ /^((9)|(10)|(11))/) {
    $self->{sysProductVersion} = "4";
  }
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::F5::F5BIGIP::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::F5::F5BIGIP::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::F5::F5BIGIP::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::lb/) {
    $self->analyze_and_check_ltm_subsystem();
  } else {
    $self->no_such_mode();
  }
}

sub analyze_ltm_subsystem {
  my $self = shift;
  $self->{components}->{ltm_subsystem} =
      Classes::F5::F5BIGIP::Component::LTMSubsystem->new('sysProductVersion' => $self->{sysProductVersion}, sysPlatformInfoMarketingName => $self->{sysPlatformInfoMarketingName});
}

package Classes::F5;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
    '1.3.6.1.4.1.3375.1.2.1.1.1', # F5-3DNS-MIB
    '1.3.6.1.4.1.3375', # F5-BIGIP-COMMON-MIB
    '1.3.6.1.4.1.3375.2.2', # F5-BIGIP-LOCAL-MIB
    '1.3.6.1.4.1.3375.2.1', # F5-BIGIP-SYSTEM-MIB
    '1.3.6.1.4.1.3375.1.1.1.1', # LOAD-BAL-SYSTEM-MIB
    '1.3.6.1.4.1.2021', # UCD-SNMP-MIB
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /Linux.*((el6.f5.x86_64)|(el5.1.0.f5app)) .*/i) {
    bless $self, 'Classes::F5::F5BIGIP';
    $self->debug('using Classes::F5::F5BIGIP');
  }
  if (ref($self) ne "Classes::F5") {
    $self->init();
  }
}

package Classes::CheckPoint::Firewall1::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{disk_subsystem} =
      Classes::CheckPoint::Firewall1::Component::DiskSubsystem->new();
  $self->{temperature_subsystem} =
      Classes::CheckPoint::Firewall1::Component::TemperatureSubsystem->new();
  $self->{fan_subsystem} =
      Classes::CheckPoint::Firewall1::Component::FanSubsystem->new();
  $self->{voltage_subsystem} =
      Classes::CheckPoint::Firewall1::Component::VoltageSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{disk_subsystem}->check();
  $self->{temperature_subsystem}->check();
  $self->{fan_subsystem}->check();
  $self->{voltage_subsystem}->check();
  if (! $self->check_messages()) {
    $self->clear_ok(); # too much noise
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{disk_subsystem}->dump();
  $self->{temperature_subsystem}->dump();
  $self->{fan_subsystem}->dump();
  $self->{voltage_subsystem}->dump();
}

package Classes::CheckPoint::Firewall1::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CHECKPOINT-MIB', [
      ['temperatures', 'sensorsTemperatureTable', 'Classes::CheckPoint::Firewall1::Component::TemperatureSubsystem::Temperature'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{temperatures}}) {
    $_->check();
  }
}


package Classes::CheckPoint::Firewall1::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub check {
  my $self = shift;
  $self->add_info(sprintf 'temperature %s is %s (%d %s)', 
      $self->{sensorsTemperatureName}, $self->{sensorsTemperatureStatus},
      $self->{sensorsTemperatureValue}, $self->{sensorsTemperatureUOM});
  if ($self->{sensorsTemperatureStatus} eq 'normal') {
    $self->add_ok();
  } elsif ($self->{sensorsTemperatureStatus} eq 'abnormal') {
    $self->add_critical();
  } else {
    $self->add_unknown();
  }
  $self->set_thresholds(warning => 60, critical => 70);
  $self->add_perfdata(
      label => 'temperature_'.$self->{sensorsTemperatureName},
      value => $self->{sensorsTemperatureValue},
  );
}

package Classes::CheckPoint::Firewall1::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CHECKPOINT-MIB', [
      ['fans', 'sensorsFanTable', 'Classes::CheckPoint::Firewall1::Component::FanSubsystem::Fan'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{fans}}) {
    $_->check();
  }
}


package Classes::CheckPoint::Firewall1::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'fan %s is %s (%d %s)', 
      $self->{sensorsFanName}, $self->{sensorsFanStatus},
      $self->{sensorsFanValue}, $self->{sensorsFanUOM});
  if ($self->{sensorsFanStatus} eq 'normal') {
    $self->add_ok();
  } elsif ($self->{sensorsFanStatus} eq 'abnormal') {
    $self->add_critical();
  } else {
    $self->add_unknown();
  }
  $self->set_thresholds(warning => 60, critical => 70);
  $self->add_perfdata(
      label => 'fan'.$self->{sensorsFanName}.'_rpm',
      value => $self->{sensorsFanValue},
  );
}

package Classes::CheckPoint::Firewall1::Component::VoltageSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CHECKPOINT-MIB', [
      ['voltages', 'sensorsVoltageTable', 'Classes::CheckPoint::Firewall1::Component::VoltageSubsystem::Voltage'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{voltages}}) {
    $_->check();
  }
}


package Classes::CheckPoint::Firewall1::Component::VoltageSubsystem::Voltage;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'voltage %s is %s (%.2f %s)', 
      $self->{sensorsVoltageName}, $self->{sensorsVoltageStatus},
      $self->{sensorsVoltageValue}, $self->{sensorsVoltageUOM});
  if ($self->{sensorsVoltageStatus} eq 'normal') {
    $self->add_ok();
  } elsif ($self->{sensorsVoltageStatus} eq 'abnormal') {
    $self->add_critical();
  } else {
    $self->add_unknown();
  }
  $self->set_thresholds(warning => 60, critical => 70);
  $self->add_perfdata(
      label => 'voltage'.$self->{sensorsVoltageName}.'_rpm',
      value => $self->{sensorsVoltageValue},
  );
}

package Classes::CheckPoint::Firewall1::Component::DiskSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('HOST-RESOURCES-MIB', [
      ['storages', 'hrStorageTable', 'Classes::HOSTRESOURCESMIB::Component::DiskSubsystem::Storage', sub { return shift->{hrStorageType} eq 'hrStorageFixedDisk'}],
  ]);
  $self->get_snmp_tables('CHECKPOINT-MIB', [
      ['volumes', 'volumesTable', 'Classes::CheckPoint::Firewall1::Component::DiskSubsystem::Volume'],
      ['disks', 'disksTable', 'Classes::CheckPoint::Firewall1::Component::DiskSubsystem::Disk'],
  ]);
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
      diskPercent diskPercent)));
}

sub check {
  my $self = shift;
  $self->add_info('checking disks');
  if (scalar (@{$self->{storages}}) == 0) {
    $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
        diskPercent diskPercent)));
    my $free = 100 - $self->{diskPercent};
    $self->add_info(sprintf 'disk has %.2f%% free space left', $free);
    $self->set_thresholds(warning => '10:', critical => '5:');
    $self->add_message($self->check_thresholds($free));
    $self->add_perfdata(
        label => 'disk_free',
        value => $free,
        uom => '%',
    );
  } else {
    foreach (@{$self->{storages}}) {
      $_->check();
    }
  }
  foreach (@{$self->{volumes}}) {
    $_->check();
  }
  foreach (@{$self->{disks}}) {
    $_->check();
  }
}


package Classes::CheckPoint::Firewall1::Component::DiskSubsystem::Volume;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'volume %s with %d disks is %s',
      $self->{volumesVolumeID},
      $self->{volumesNumberOfDisks},
      $self->{volumesVolumeState});
  if ($self->{volumesVolumeState} eq 'degraded') {
    $self->add_warning();
  } elsif ($self->{volumesVolumeState} eq 'failed') {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
  
}


package Classes::CheckPoint::Firewall1::Component::DiskSubsystem::Disk;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'disk %s (vol %s) is %s',
      $self->{disksIndex},
      $self->{disksVolumeID},
      $self->{disksState});
  # warning/critical comes from the volume
}

package Classes::CheckPoint::Firewall1::Component::MngmtSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::mngmt::status/) {
    $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
        mgStatShortDescr mgStatLongDescr)));
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking mngmt');
  if ($self->mode =~ /device::mngmt::status/) {
    if (! defined $self->{mgStatShortDescr}) {
      $self->add_unknown('management mib is not implemented');
    } elsif ($self->{mgStatShortDescr} ne 'OK') {
      $self->add_critical(sprintf 'status of management is %s', $self->{mgStatLongDescr});
    } else {
      $self->add_ok(sprintf 'status of management is %s', $self->{mgStatLongDescr});
    }
  }
}

package Classes::CheckPoint::Firewall1::Component::SvnSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::svn::status/) {
    $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
        svnStatShortDescr svnStatLongDescr)));
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking svn');
  if ($self->mode =~ /device::svn::status/) {
    if ($self->{svnStatShortDescr} ne 'OK') {
      $self->add_critical(sprintf 'status of svn is %s', $self->{svnStatLongDescr});
    } else {
      $self->add_ok(sprintf 'status of svn is %s', $self->{svnStatLongDescr});
    }
  }
}

package Classes::CheckPoint::Firewall1::Component::FwSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
      fwModuleState fwPolicyName fwNumConn)));
  if ($self->mode =~ /device::fw::policy::installed/) {
  } elsif ($self->mode =~ /device::fw::policy::connections/) {
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking fw module');
  if ($self->{fwModuleState} ne 'Installed') {
    $self->add_critical(sprintf 'fw module is %s', $self->{fwPolicyName});
  } elsif ($self->mode =~ /device::fw::policy::installed/) {
    if (! $self->opts->name()) {
      $self->add_unknown('please specify a policy with --name');
    } elsif ($self->{fwPolicyName} eq $self->opts->name()) {
      $self->add_ok(sprintf 'fw policy is %s', $self->{fwPolicyName});
    } else {
      $self->add_critical(sprintf 'fw policy is %s, expected %s',
          $self->{fwPolicyName}, $self->opts->name());
    }
  } elsif ($self->mode =~ /device::fw::policy::connections/) {
    $self->set_thresholds(warning => 20000, critical => 23000);
    $self->add_message($self->check_thresholds($self->{fwNumConn}),
        sprintf 'policy %s has %s open connections',
            $self->{fwPolicyName}, $self->{fwNumConn});
    $self->add_perfdata(
        label => 'fw_policy_numconn',
        value => $self->{fwNumConn},
    );
  }
}

package Classes::CheckPoint::Firewall1::Component::HaSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub init {
  my $self = shift;
  if ($self->mode =~ /device::ha::role/) {
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
      haStarted haState haStatShort)));
    if (! $self->opts->role()) {
      $self->opts->override_opt('role', 'active');
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking ha');
  $self->add_info(sprintf 'ha %sstarted, role is %s, status is %s', 
      $self->{haStarted} eq 'yes' ? '' : 'not ', 
      $self->{haState}, $self->{haStatShort});
  if ($self->{haStarted} eq 'yes') {
    if ($self->{haStatShort} ne 'OK') {
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : CRITICAL,
          $self->{info});
    } elsif ($self->{haState} ne $self->opts->role()) {
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
          $self->{info});
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
          sprintf "expected role %s", $self->opts->role())
    } else {
      $self->add_ok();
    }
  } else {
    $self->add_message(
        defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
        'ha was not started');
  }
}

package Classes::CheckPoint::Firewall1::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
      procUsage)));
  $self->{procQueue} = $self->valid_response('CHECKPOINT-MIB', 'procQueue');
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{procUsage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{procUsage}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{procUsage},
      uom => '%',
  );
  if (defined $self->{procQueue}) {
    $self->add_perfdata(
        label => 'cpu_queue_length',
        value => $self->{procQueue},
        thresholds => 0,
    );
  }
}

package Classes::CheckPoint::Firewall1::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CHECKPOINT-MIB', (qw(
      memTotalReal64 memFreeReal64)));
  $self->{memory_usage} = $self->{memFreeReal64} ? 
      ( ($self->{memTotalReal64} - $self->{memFreeReal64}) / $self->{memTotalReal64} * 100) : 100;
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'memory usage is %.2f%%', $self->{memory_usage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{memory_usage}));
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{memory_usage},
      uom => '%',
  );
}

package Classes::CheckPoint::Firewall1;
our @ISA = qw(Classes::CheckPoint);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::CheckPoint::Firewall1::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::CheckPoint::Firewall1::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::CheckPoint::Firewall1::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::ha::/) {
    $self->analyze_and_check_ha_subsystem("Classes::CheckPoint::Firewall1::Component::HaSubsystem");
  } elsif ($self->mode =~ /device::fw::/) {
    $self->analyze_and_check_fw_subsystem("Classes::CheckPoint::Firewall1::Component::FwSubsystem");
  } elsif ($self->mode =~ /device::svn::/) {
    $self->analyze_and_check_svn_subsystem("Classes::CheckPoint::Firewall1::Component::SvnSubsystem");
  } elsif ($self->mode =~ /device::mngmt::/) {
    # not sure if this works fa25239716cb74c672f8dd390430dc4056caffa7
    $self->analyze_and_check_mngmt_subsystem("Classes::CheckPoint::Firewall1::Component::MngmtSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::CheckPoint;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
    '1.3.6.1.4.1.2620', # CHECKPOINT-MIB
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /(FireWall\-1\s)|(cpx86_64)|(Linux.*\dcp )/i) {
    bless $self, 'Classes::CheckPoint::Firewall1';
    $self->debug('using Classes::CheckPoint::Firewall1');
  }
  if (ref($self) ne "Classes::CheckPoint") {
    $self->init();
  }
}

package Classes::Clavister::Firewall1::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;
use Data::Dumper;

sub init {
  my $self = shift;
  $self->get_snmp_tables('CLAVISTER-MIB', [
      ['sensor', 'clvHWSensorEntry', 'Classes::Clavister::Firewall1::Component::HWSensor'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{sensor}}) {
    $_->check();
  }
}


package Classes::Clavister::Firewall1::Component::HWSensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  if ($self->{clvHWSensorName} =~ /Fan/i) {
    $self->add_info(sprintf '%s is running (%d %s)', 
        $self->{clvHWSensorName}, $self->{clvHWSensorValue}, $self->{clvHWSensorUnit});
    $self->set_thresholds(warning => "6000:7500", critical => "1000:10000");
    $self->add_message($self->check_thresholds($self->{clvHWSensorValue}));
    $self->add_perfdata(
        label => $self->{clvHWSensorName}.'_rpm',
        value => $self->{clvHWSensorValue},
    );
  } elsif ($self->{clvHWSensorName} =~ /Temp/i) {
    $self->add_info(sprintf '%s is running (%d %s)',
        $self->{clvHWSensorName}, $self->{clvHWSensorValue}, $self->{clvHWSensorUnit});
    $self->set_thresholds(warning => 60, critical => 70);
    $self->add_message($self->check_thresholds($self->{clvHWSensorValue}));
    $self->add_perfdata(
        label => $self->{clvHWSensorName}.'_'.$self->{clvHWSensorUnit},
        value => $self->{clvHWSensorValue},
    );
  }
}

package Classes::Clavister::Firewall1::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CLAVISTER-MIB', (qw(
      clvSysCpuLoad)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{clvSysCpuLoad});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{clvSysCpuLoad}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{clvSysCpuLoad},
      uom => '%',
  );
}

package Classes::Clavister::Firewall1::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('CLAVISTER-MIB', (qw(
      clvSysMemUsage)));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'memory usage is %.2f%%', $self->{clvSysMemUsage});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{clvSysMemUsage}));
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{clvSysMemUsage},
      uom => '%',
  );
}

package Classes::Clavister::Firewall1;
our @ISA = qw(Classes::Clavister);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Clavister::Firewall1::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Clavister::Firewall1::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Clavister::Firewall1::Component::MemSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Clavister;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
    '1.3.6.1.4.1.5089', # CLAVISTER-MIB
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /Clavister/i) {
    bless $self, 'Classes::Clavister::Firewall1';
    $self->debug('using Classes::Clavister::Firewall1');
  }
  if (ref($self) ne "Classes::Clavister") {
    $self->init();
  }
}

package Classes::SGOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  # https://kb.bluecoat.com/index?page=content&id=KB3069
  # Memory pressure simply is the percentage of physical memory less free and reclaimable memory, of total memory. So, for example, if there is no free or reclaimable memory in the system, then memory pressure is at 100%.
  # The event logs start reporting memory pressure when it is over 75%.
  # There's two separate OIDs to obtain memory pressure value for SGOSV4 and SGOSV5;
  # SGOSV4:  memPressureValue - OIDs: 1.3.6.1.4.1.3417.2.8.2.3 (systemResourceMIB)
  # SGOSV5: sgProxyMemoryPressure - OIDs: 1.3.6.1.4.1.3417.2.11.2.3.4 (bluecoatSGProxyMIB)
  $self->get_snmp_objects('BLUECOAT-SG-PROXY-MIB', (qw(sgProxyMemPressure
      sgProxyMemAvailable sgProxyMemCacheUsage sgProxyMemSysUsage)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'memory usage is %.2f%%',
      $self->{sgProxyMemPressure});
  $self->set_thresholds(warning => 75, critical => 90);
  $self->add_message($self->check_thresholds($self->{sgProxyMemPressure}));
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{sgProxyMemPressure},
      uom => '%',
  );
}

package Classes::SGOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my %params = @_;
  # With AVOS version 5.5.4.1, 5.4.6.1 and 6.1.2.1, the SNMP MIB has been extended to support multiple CPU cores.
  # The new OID is defined as a table 1.3.6.1.4.1.3417.2.11.2.4.1 in the BLUECOAT-SG-PROXY-MIB file with the following sub-OIDs.
  # https://kb.bluecoat.com/index?page=content&id=FAQ1244&actp=search&viewlocale=en_US&searchid=1360452047002
  $self->get_snmp_tables('BLUECOAT-SG-PROXY-MIB', [
      ['cpus', 'sgProxyCpuCoreTable', 'Classes::SGOS::Component::CpuSubsystem::Cpu'],
  ]);
  if (scalar (@{$self->{cpus}}) == 0) {
    $self->get_snmp_tables('USAGE-MIB', [
        ['cpus', 'deviceUsageTable', 'Classes::SGOS::Component::CpuSubsystem::DevCpu', sub { return shift->{deviceUsageName} =~ /CPU/ }],
    ]);
  }
}

package Classes::SGOS::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s usage is %.2f%%',
      $self->{flat_indices}, $self->{sgProxyCpuCoreBusyPerCent});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{sgProxyCpuCoreBusyPerCent}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{flat_indices}.'_usage',
      value => $self->{sgProxyCpuCoreBusyPerCent},
      uom => '%',
  );
}


package Classes::SGOS::Component::CpuSubsystem::DevCpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s usage is %.2f%%',
      $self->{flat_indices}, $self->{deviceUsagePercent});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{deviceUsagePercent}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{flat_indices}.'_usage',
      value => $self->{deviceUsagePercent},
      uom => '%',
  );
}


package Classes::SGOS::Component::EnvironmentalSubsystem;
our @ISA = qw(Classes::SGOS);
use strict;

sub new {
  my $class = shift;
  my $self = {};
  bless $self, $class;
  $self->init();
  return $self;
}

sub init {
  my $self = shift;
  $self->{sensor_subsystem} =
      Classes::SGOS::Component::SensorSubsystem->new();
  $self->{disk_subsystem} =
      Classes::SGOS::Component::DiskSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{sensor_subsystem}->check();
  $self->{disk_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{sensor_subsystem}->dump();
  $self->{disk_subsystem}->dump();
}


package Classes::SGOS::Component::SensorSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('SENSOR-MIB', [
      ['sensors', 'deviceSensorValueTable', 'Classes::SGOS::Component::SensorSubsystem::Sensor'],
  ]);
}

sub check {
  my $self = shift;
  my $psus = {};
  foreach my $sensor (@{$self->{sensors}}) {
    if ($sensor->{deviceSensorName} =~ /^PSU\s+(\d+)\s+(.*)/) {
      $psus->{$1}->{sensors}->{$2}->{code} = $sensor->{deviceSensorCode};
      $psus->{$1}->{sensors}->{$2}->{status} = $sensor->{deviceSensorStatus};
    }
  }
  foreach my $psu (keys %{$psus}) {
    if ($psus->{$psu}->{sensors}->{'ambient temperature'}->{code} &&
        $psus->{$psu}->{sensors}->{'ambient temperature'}->{code} eq 'unknown' &&
        $psus->{$psu}->{sensors}->{'ambient temperature'}->{status} &&
        $psus->{$psu}->{sensors}->{'ambient temperature'}->{status} eq 'nonoperational' &&
        $psus->{$psu}->{sensors}->{'core temperature'}->{code} &&
        $psus->{$psu}->{sensors}->{'core temperature'}->{code} eq 'unknown' &&
        $psus->{$psu}->{sensors}->{'core temperature'}->{status} &&
        $psus->{$psu}->{sensors}->{'core temperature'}->{status} eq 'nonoperational' &&
        $psus->{$psu}->{sensors}->{'status'}->{code} &&
        $psus->{$psu}->{sensors}->{'status'}->{code} eq 'no-power' &&
        $psus->{$psu}->{sensors}->{'status'}->{status} &&
        $psus->{$psu}->{sensors}->{'status'}->{status} eq 'ok') {
      $psus->{$psu}->{'exists'} = 0;
      $self->add_info(sprintf 'psu %d probably doesn\'t exist', $psu);
    } else {
      $psus->{$psu}->{'exists'} = 1;
    }
  }
  foreach my $sensor (@{$self->{sensors}}) {
    if ($sensor->{deviceSensorName} =~ /^PSU\s+(\d+)\s+(.*)/) {
      if (! $psus->{$1}->{exists}) {
        $sensor->{deviceSensorCode} = sprintf 'not-installed (real code: %s)',
            $sensor->{deviceSensorCode};
        $sensor->blacklist();
      }
    }
  }
  foreach my $sensor (@{$self->{sensors}}) {
    $sensor->check();
  }
}


package Classes::SGOS::Component::SensorSubsystem::Sensor;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  if ($self->{deviceSensorScale}) {
    $self->{deviceSensorValue} *= 10 ** $self->{deviceSensorScale};
  }
  $self->add_info(sprintf 'sensor %s (%s %s) is %s',
      $self->{deviceSensorName},
      $self->{deviceSensorValue},
      $self->{deviceSensorUnits},
      $self->{deviceSensorCode});
  if ($self->{deviceSensorCode} =~ /^not-installed/) {
  } elsif ($self->{deviceSensorCode} eq "unknown") {
  } else {
    if ($self->{deviceSensorCode} ne "ok") {
      if ($self->{deviceSensorCode} =~ /warning/) {
        $self->add_warning();
      } else {
        $self->add_critical();
      }
    }
    $self->add_perfdata(
        label => sprintf('sensor_%s', $self->{deviceSensorName}),
        value => $self->{deviceSensorValue},
    ) if $self->{deviceSensorUnits} =~ /^(volts|celsius|rpm)/;
  }
}

package Classes::SGOS::Component::DiskSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('DISK-MIB', [
      ['disks', 'deviceDiskValueTable', 'Classes::SGOS::Component::DiskSubsystem::Disk'],
  ]);
  $self->get_snmp_tables('USAGE-MIB', [
      ['filesystems', 'deviceUsageTable', 'Classes::SGOS::Component::DiskSubsystem::FS', sub { return lc shift->{deviceUsageName} eq 'disk' }],
  ]);
  my $fs = 0;
  foreach (@{$self->{filesystems}}) {
    $_->{deviceUsageIndex} = $fs++;
  }
}


package Classes::SGOS::Component::DiskSubsystem::Disk;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'disk %s (%s %s) is %s',
      $self->{flat_indices},
      $self->{deviceDiskVendor},
      $self->{deviceDiskRevision},
      $self->{deviceDiskStatus});
  if ($self->{deviceDiskStatus} eq "bad") {
    $self->add_critical();
  }
}


package Classes::SGOS::Component::DiskSubsystem::FS;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'disk %s usage is %.2f%%',
      $self->{deviceUsageIndex},
      $self->{deviceUsagePercent});
  if ($self->{deviceUsageStatus} ne "ok") {
    $self->add_critical();
  } else {
    $self->add_ok();
  }
  $self->add_perfdata(
      label => 'disk_'.$self->{deviceUsageIndex}.'_usage',
      value => $self->{deviceUsagePercent},
      uom => '%',
      warning => $self->{deviceUsageHigh},
      critical => $self->{deviceUsageHigh}
  );
}


package Classes::SGOS::Component::SecuritySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('ATTACK-MIB', [
      ['attacks', 'deviceAttackTable', 'Classes::SGOS::Component::SecuritySubsystem::Attack' ],
  ]);
}

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking attacks');
  if (scalar (@{$self->{attacks}}) == 0) {
    $self->add_info('no security incidents');
  } else {
    foreach (@{$self->{attacks}}) {
      $_->check();
    }
    $self->add_info(sprintf '%d serious incidents (of %d)',
        scalar(grep { $_->{count_me} == 1 } @{$self->{attacks}}),
        scalar(@{$self->{attacks}}));
  }
  $self->add_ok();
}


package Classes::SGOS::Component::SecuritySubsystem::Attack;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{deviceAttackTime} = $self->timeticks(
      $self->{deviceAttackTime});
  $self->{count_me} = 0;
  $self->add_info(sprintf '%s %s %s',
      scalar localtime (time - $self->uptime() + $self->{deviceAttackTime}),
      $self->{deviceAttackName}, $self->{deviceAttackStatus});
  my $lookback = $self->opts->lookback() ? 
      $self->opts->lookback() : 3600;
  if (($self->{deviceAttackStatus} eq 'under-attack') &&
      ($lookback - $self->uptime() + $self->{deviceAttackTime} > 0)) {
    $self->add_critical();
    $self->{count_me}++;
  }
}

package Classes::SGOS::Component::ConnectionSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub init {
  my $self = shift;
  $self->get_snmp_objects('BLUECOAT-SG-PROXY-MIB', (qw(sgProxyHttpResponseTimeAll
      sgProxyHttpResponseFirstByte
      sgProxyHttpResponseByteRate sgProxyHttpResponseSize
      sgProxyHttpClientConnections sgProxyHttpClientConnectionsActive
      sgProxyHttpClientConnectionsIdle
      sgProxyHttpServerConnections sgProxyHttpServerConnectionsActive
      sgProxyHttpServerConnectionsIdle)));
  $self->{sgProxyHttpResponseTimeAll} /= 1000;
}

sub check {
  my $self = shift;
  $self->add_info('checking connections');
  if ($self->mode =~ /device::connections::check/) {
    $self->add_info(sprintf 'average service time for http requests is %.5fs',
        $self->{sgProxyHttpResponseTimeAll});
    $self->set_thresholds(warning => 5, critical => 10);
    $self->add_message($self->check_thresholds($self->{sgProxyHttpResponseTimeAll}));
    $self->add_perfdata(
        label => 'http_response_time',
        value => $self->{sgProxyHttpResponseTimeAll},
        places => 5,
        uom => 's',
    );
  } elsif ($self->mode =~ /device::.*?::count/) {
    my $details = [
        ['client', 'total', 'sgProxyHttpClientConnections'],
        ['client', 'active', 'sgProxyHttpClientConnectionsActive'],
        ['client', 'idle', 'sgProxyHttpClientConnectionsIdle'],
        ['server', 'total', 'sgProxyHttpServerConnections'],
        ['server', 'active', 'sgProxyHttpServerConnectionsActive'],
        ['server', 'idle', 'sgProxyHttpServerConnectionsIdle'],
    ];
    my @selected;
    # --name client --name2 idle
    if (! $self->opts->name) {
      @selected = @{$details};
    } elsif (! $self->opts->name2) {
      @selected = grep { $_->[0] eq $self->opts->name } @{$details};
    } else {
      @selected = grep { $_->[0] eq $self->opts->name && $_->[1] eq $self->opts->name2 } @{$details};
    }
    foreach (@selected) {
      $self->add_info(sprintf '%d %s connections %s', $self->{$_->[2]}, $_->[0], $_->[1]);
      $self->set_thresholds(warning => 5000, critical => 10000);
      $self->add_message($self->check_thresholds($self->{$_->[2]}));
      $self->add_perfdata(
          label => $_->[0].'_connections_'.$_->[1],
          value => $self->{$_->[2]},
      );
    }
  }
}


package Classes::SGOS;
our @ISA = qw(Classes::Bluecoat);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::SGOS::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::SGOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::SGOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::security/) {
    $self->analyze_and_check_security_subsystem("Classes::SGOS::Component::SecuritySubsystem");
  } elsif ($self->mode =~ /device::(users|connections)::(count|check)/) {
    $self->analyze_and_check_connection_subsystem("Classes::SGOS::Component::ConnectionSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::AVOS::Component::KeySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('BLUECOAT-AV-MIB', (qw(
      avLicenseDaysRemaining avVendorName)));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'license %s expires in %d days',
      $self->{avVendorName},
      $self->{avLicenseDaysRemaining});
  $self->set_thresholds(warning => '14:', critical => '7:');
  $self->add_message($self->check_thresholds($self->{avLicenseDaysRemaining}));
  $self->add_perfdata(
      label => sprintf('lifetime_%s', $self->{avVendorName}),
      value => $self->{avLicenseDaysRemaining},
  );
}


package Classes::AVOS::Component::SecuritySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('BLUECOAT-AV-MIB', (qw(
      avVirusesDetected)));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf '%d viruses detected',
      $self->{avVirusesDetected});
  $self->set_thresholds(warning => 1500, critical => 1500);
  $self->add_message($self->check_thresholds($self->{avVirusesDetected}));
  $self->add_perfdata(
      label => 'viruses',
      value => $self->{avVirusesDetected},
  );
}

package Classes::AVOS::Component::ConnectionSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('BLUECOAT-AV-MIB', (qw(
      avSlowICAPConnections)));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf '%d slow ICAP connections',
      $self->{avSlowICAPConnections});
  $self->set_thresholds(warning => 100, critical => 100);
  $self->add_message($self->check_thresholds($self->{avSlowICAPConnections}));
  $self->add_perfdata(
      label => 'slow_connections',
      value => $self->{avSlowICAPConnections},
  );
}

package Classes::AVOS::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  # https://kb.bluecoat.com/index?page=content&id=KB3069
  # Memory pressure simply is the percentage of physical memory less free and reclaimable memory, of total memory. So, for example, if there is no free or reclaimable memory in the system, then memory pressure is at 100%.
  # The event logs start reporting memory pressure when it is over 75%.
  # There's two separate OIDs to obtain memory pressure value for AVOSV4 and AVOSV5;
  # AVOSV4:  memPressureValue - OIDs: 1.3.6.1.4.1.3417.2.8.2.3 (systemResourceMIB)
  # AVOSV5: sgProxyMemoryPressure - OIDs: 1.3.6.1.4.1.3417.2.11.2.3.4 (bluecoatSGProxyMIB)
  my $self = shift;
  $self->get_snmp_objects('BLUECOAT-SG-PROXY-MIB', (qw(
      sgProxyMemPressure sgProxyMemAvailable sgProxyMemCacheUsage sgProxyMemSysUsage)));
  if (! defined $self->{sgProxyMemPressure}) {
  $self->get_snmp_objects('SYSTEM-RESOURCES-MIB', (qw(
      memPressureValue memWarningThreshold memCriticalThreshold memCurrentState)));
  }
  if (! defined $self->{memPressureValue}) {
    foreach ($self->get_snmp_table_objects(
        'USAGE-MIB', 'deviceUsageTable')) {
      next if $_->{deviceUsageName} !~ /Memory/;
      $self->{deviceUsageName} = $_->{deviceUsageName};
      $self->{deviceUsagePercent} = $_->{deviceUsagePercent};
      $self->{deviceUsageHigh} = $_->{deviceUsageHigh};
      $self->{deviceUsageStatus} = $_->{deviceUsageStatus};
      $self->{deviceUsageTime} = $_->{deviceUsageTime};
    }
    bless $self, 'Classes::AVOS::Component::MemSubsystem::AVOS3';
  }
}


package Classes::AVOS::Component::MemSubsystem::AVOS3;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking memory');
  $self->add_info(sprintf 'memory usage is %.2f%%',
      $self->{deviceUsagePercent});
  $self->set_thresholds(warning => $self->{deviceUsageHigh} - 10, critical => $self->{deviceUsageHigh});
  $self->add_message($self->check_thresholds($self->{deviceUsagePercent}));
  $self->add_perfdata(
      label => 'memory_usage',
      value => $self->{deviceUsagePercent},
      uom => '%',
  );
}

package Classes::AVOS::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my %params = @_;
  # With AVOS version 5.5.4.1, 5.4.6.1 and 6.1.2.1, the SNMP MIB has been extended to support multiple CPU cores.
  # The new OID is defined as a table 1.3.6.1.4.1.3417.2.11.2.4.1 in the BLUECOAT-SG-PROXY-MIB file with the following sub-OIDs.
  # https://kb.bluecoat.com/index?page=content&id=FAQ1244&actp=search&viewlocale=en_US&searchid=1360452047002
  $self->get_snmp_tables('BLUECOAT-SG-PROXY-MIB', [
      ['cpus', 'sgProxyCpuCoreTable', 'Classes::AVOS::Component::CpuSubsystem::Cpu'],
  ]);
  if (scalar (@{$self->{cpus}}) == 0) {
    $self->get_snmp_tables('USAGE-MIB', [
        ['cpus', 'deviceUsageTable', 'Classes::AVOS::Component::CpuSubsystem::DevCpu', sub { return shift->{deviceUsageName} =~ /CPU/ }],
    ]);
  }
}

package Classes::AVOS::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s usage is %.2f%%',
      $self->{sgProxyCpuCoreIndex}, $self->{sgProxyCpuCoreBusyPerCent});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{sgProxyCpuCoreBusyPerCent}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{sgProxyCpuCoreIndex}.'_usage',
      value => $self->{sgProxyCpuCoreBusyPerCent},
      uom => '%',
  );
}


package Classes::AVOS::Component::CpuSubsystem::DevCpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'cpu %s usage is %.2f%%',
      $self->{deviceUsageIndex}, $self->{deviceUsagePercent});
  $self->set_thresholds(warning => $self->{deviceUsageHigh} - 10, critical => $self->{deviceUsageHigh});
  $self->add_message($self->check_thresholds($self->{deviceUsagePercent}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{deviceUsageIndex}.'_usage',
      value => $self->{deviceUsagePercent},
      uom => '%',
  );
}


package Classes::AVOS;
our @ISA = qw(Classes::Bluecoat);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::AVOS::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::AVOS::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::licenses::/) {
    $self->analyze_and_check_key_subsystem("Classes::AVOS::Component::KeySubsystem");
  } elsif ($self->mode =~ /device::connections/) {
    $self->analyze_and_check_connection_subsystem("Classes::AVOS::Component::ConnectionSubsystem");
  } elsif ($self->mode =~ /device::security/) {
    $self->analyze_and_check_security_subsystem("Classes::AVOS::Component::SecuritySubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Foundry::Component::SLBSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub update_caches {
  my $self = shift;
  my $force = shift;
  $self->update_entry_cache($force, 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4BindTable', 'snL4BindVirtualServerName');
  $self->update_entry_cache($force, 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerTable', 'snL4VirtualServerName');
  $self->update_entry_cache($force, 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortTable', 'snL4VirtualServerPortServerName');
  $self->update_entry_cache($force, 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortStatisticTable', 'snL4VirtualServerPortStatisticServerName');
  $self->update_entry_cache($force, 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerPortStatusTable', 'snL4RealServerPortStatusServerName');
}

sub init {
  my $self = shift;
  # opt->name can be servername:serverport
  my $original_name = $self->opts->name;
  if ($self->mode =~ /device::lb::session::usage/) {
    $self->get_snmp_objects('FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', (qw(
        snL4MaxSessionLimit snL4FreeSessionCount)));
    $self->{session_usage} = 100 * ($self->{snL4MaxSessionLimit} - $self->{snL4FreeSessionCount}) / $self->{snL4MaxSessionLimit};
  } elsif ($self->mode =~ /device::lb::pool/) {
    if ($self->mode =~ /device::lb::pool::list/) {
      $self->update_caches(1);
    } else {
      $self->update_caches(0);
    }
    if ($self->opts->name) {
      # optimized, with a minimum of snmp operations
      foreach my $vs ($self->get_snmp_table_objects_with_cache(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerTable', 'snL4VirtualServerName')) {
        $self->{vsdict}->{$vs->{snL4VirtualServerName}} = $vs;
        $self->opts->override_opt('name', $vs->{snL4VirtualServerName});
        foreach my $vsp ($self->get_snmp_table_objects_with_cache(
            'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortTable', 'snL4VirtualServerPortServerName')) {
          $self->{vspdict}->{$vsp->{snL4VirtualServerPortServerName}}->{$vsp->{snL4VirtualServerPortPort}} = $vsp;
        }
        foreach my $vspsc ($self->get_snmp_table_objects_with_cache(
            'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortStatisticTable', 'snL4VirtualServerPortStatisticServerName')) {
          $self->{vspscdict}->{$vspsc->{snL4VirtualServerPortStatisticServerName}}->{$vspsc->{snL4VirtualServerPortStatisticPort}} = $vspsc;
        }
        foreach my $binding ($self->get_snmp_table_objects_with_cache(
            'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4BindTable', 'snL4BindVirtualServerName')) {
          $self->{bindingdict}->{$binding->{snL4BindVirtualServerName}}->{$binding->{snL4BindVirtualPortNumber}}->{$binding->{snL4BindRealServerName}}->{$binding->{snL4BindRealPortNumber}} = 1;
          $self->opts->override_opt('name', $binding->{snL4BindRealServerName});
          if (! exists $self->{rsdict}->{$binding->{snL4BindRealServerName}}) {
            #foreach my $rs ($self->get_snmp_table_objects_with_cache(
            #    'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerTable', 'snL4RealServerName')) {
            #  $self->{rsdict}->{$rs->{snL4RealServerName}} = $rs;
            #}
            #foreach my $rsst ($self->get_snmp_table_objects_with_cache(
            #    'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerStatusTable', 'snL4RealServerStatusName')) {
            #  $self->{rsstdict}->{$rsst->{snL4RealServerStatusName}} = $rsst;
            #}
          }
          if (! exists $self->{rspstdict}->{$binding->{snL4BindRealServerName}}->{$binding->{snL4BindRealPortNumber}}) {
            # todo: profiler, dauert 30s pro aufruf
            foreach my $rspst ($self->get_snmp_table_objects_with_cache(
                'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerPortStatusTable', 'snL4RealServerPortStatusServerName')) {
              $self->{rspstdict}->{$rspst->{snL4RealServerPortStatusServerName}}->{$rspst->{snL4RealServerPortStatusPort}} = $rspst;
            }
          }
        }
      }
    } else {
      foreach my $vs ($self->get_snmp_table_objects(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerTable')) {
        $self->{vsdict}->{$vs->{snL4VirtualServerName}} = $vs;
      }
      foreach my $vsp ($self->get_snmp_table_objects(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortTable')) {
        $self->{vspdict}->{$vsp->{snL4VirtualServerPortServerName}}->{$vsp->{snL4VirtualServerPortPort}} = $vsp;
      }
      foreach my $vspsc ($self->get_snmp_table_objects(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4VirtualServerPortStatisticTable')) {
        $self->{vspscdict}->{$vspsc->{snL4VirtualServerPortStatisticServerName}}->{$vspsc->{snL4VirtualServerPortStatisticPort}} = $vspsc;
      }
      #foreach my $rs ($self->get_snmp_table_objects(
      #    'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerTable')) {
      #  $self->{rsdict}->{$rs->{snL4RealServerName}} = $rs;
      #}
      #foreach my $rsst ($self->get_snmp_table_objects(
      #    'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerStatusTable')) {
      #  $self->{rsstdict}->{$rsst->{snL4RealServerStatusName}} = $rsst;
      #}
      foreach my $rspst ($self->get_snmp_table_objects(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4RealServerPortStatusTable')) {
        $self->{rspstdict}->{$rspst->{snL4RealServerPortStatusServerName}}->{$rspst->{snL4RealServerPortStatusPort}} = $rspst;
      }
      foreach my $binding ($self->get_snmp_table_objects(
          'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB', 'snL4BindTable')) {
        $self->{bindingdict}->{$binding->{snL4BindVirtualServerName}}->{$binding->{snL4BindVirtualPortNumber}}->{$binding->{snL4BindRealServerName}}->{$binding->{snL4BindRealPortNumber}} = 1;
      }
    }

    # snL4VirtualServerTable:                snL4VirtualServerAdminStatus
    # snL4VirtualServerStatisticTable:       allenfalls TxRx Bytes
    # snL4VirtualServerPortTable:            snL4VirtualServerPortAdminStatus*
    # snL4VirtualServerPortStatisticTable:   snL4VirtualServerPortStatisticCurrentConnection*
    # snL4RealServerTable:                   snL4RealServerAdminStatus
    # snL4RealServerPortStatusTable:         snL4RealServerPortStatusCurrentConnection snL4RealServerPortStatusState
    # 
    # summe snL4RealServerStatisticCurConnections = snL4VirtualServerPortStatisticCurrentConnection
    # vip , jeder vport gibt ein performancedatum, jeder port hat n. realports, jeder realport hat status
    #  aus realportstatus errechnet sich verfuegbarkeit des vport
    #  aus vports ergeben sich die session-output.zahlen
    # real ports eines vs, real servers
    # globaler mode snL4MaxSessionLimit : snL4FreeSessionCount


    #
    # virtual server
    #
    $self->opts->override_opt('name', $original_name);
    $self->{virtualservers} = [];
    foreach my $vs (grep { $self->filter_name($_) } keys %{$self->{vsdict}}) {
      $self->{vsdict}->{$vs} = Classes::Foundry::Component::SLBSubsystem::VirtualServer->new(%{$self->{vsdict}->{$vs}});
      next if ! exists $self->{vspdict}->{$vs};
      #
      # virtual server has ports
      #
      foreach my $vspp (keys %{$self->{vspdict}->{$vs}}) {
        next if $self->opts->name2 && $self->opts->name2 ne $vspp;
        #
        # virtual server port has bindings
        #
        $self->{vspdict}->{$vs}->{$vspp} = Classes::Foundry::Component::SLBSubsystem::VirtualServerPort->new(%{$self->{vspdict}->{$vs}->{$vspp}});
        #
        # merge virtual server port and virtual server port statistics
        #
        map { $self->{vspdict}->{$vs}->{$vspp}->{$_} = $self->{vspscdict}->{$vs}->{$vspp}->{$_} } keys %{$self->{vspscdict}->{$vs}->{$vspp}};
        #
        # add the virtual port to the virtual server object
        #
        $self->{vsdict}->{$vs}->add_port($self->{vspdict}->{$vs}->{$vspp});
        next if ! exists $self->{bindingdict}->{$vs} || ! exists $self->{bindingdict}->{$vs}->{$vspp};
        #
        # bound virtual server port has corresponding real server port(s)
        #
        foreach my $rs (keys %{$self->{bindingdict}->{$vs}->{$vspp}}) {
          foreach my $rsp (keys %{$self->{bindingdict}->{$vs}->{$vspp}->{$rs}}) {
            #
            # loop through real server / real server port
            #
            $self->{rspstdict}->{$rs}->{$rsp} = Classes::Foundry::Component::SLBSubsystem::RealServerPort->new(%{$self->{rspstdict}->{$rs}->{$rsp}}) if ref($self->{rspstdict}->{$rs}->{$rsp}) eq 'HASH';
            $self->{vspdict}->{$vs}->{$vspp}->add_port($self->{rspstdict}->{$rs}->{$rsp}); # add real port(s) to virtual port
          }
        }
      }
      push(@{$self->{virtualservers}}, $self->{vsdict}->{$vs});
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking slb virtual servers');
  if ($self->mode =~ /device::lb::session::usage/) {
    $self->add_info('checking session usage');
    $self->add_info(sprintf 'session usage is %.2f%% (%d of %d)', $self->{session_usage},
        $self->{snL4MaxSessionLimit} - $self->{snL4FreeSessionCount}, $self->{snL4MaxSessionLimit});
    $self->set_thresholds(warning => 80, critical => 90);
    $self->add_message($self->check_thresholds($self->{session_usage}));
    $self->add_perfdata(
        label => 'session_usage',
        value => $self->{session_usage},
        uom => '%',
    );
  } elsif ($self->mode =~ /device::lb::pool/) {
    if (scalar(@{$self->{virtualservers}}) == 0) {
      $self->add_unknown('no vips');
      return;
    }
    if ($self->mode =~ /pool::list/) {
      foreach (@{$self->{virtualservers}}) {
        printf "%s\n", $_->{snL4VirtualServerName};
        #$_->list();
      }
    } else {
      foreach (@{$self->{virtualservers}}) {
        $_->check();
      }
      if (! $self->opts->name) {
        $self->clear_ok(); # too much noise
        if (! $self->check_messages()) {
          $self->add_ok("virtual servers working fine");
        }
      }
    }
  }
}


package Classes::Foundry::Component::SLBSubsystem::VirtualServer;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{ports} = [];
}

sub check {
  my $self = shift;
  my %params = @_;
  $self->add_info(sprintf "vis %s is %s", 
      $self->{snL4VirtualServerName},
      $self->{snL4VirtualServerAdminStatus});
  if ($self->{snL4VirtualServerAdminStatus} ne 'enabled') {
    $self->add_warning();
  } else {
    if (scalar (@{$self->{ports}}) == 0) {
      $self->add_warning();
      $self->add_warning("but has no configured ports");
    } else {
      foreach (@{$self->{ports}}) {
        $_->check();
      }
    }
  }
  if ($self->opts->report eq "html") {
    my ($code, $message) = $self->check_messages();
    printf "%s - %s%s\n", $self->status_code($code), $message, $self->perfdata_string() ? " | ".$self->perfdata_string() : "";
    $self->suppress_messages();
    print $self->html_string();
  }
}

sub add_port {
  my $self = shift;
  push(@{$self->{ports}}, shift);
}


package Classes::Foundry::Component::SLBSubsystem::VirtualServerPort;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my $self = shift;
  $self->{ports} = [];
}

sub check {
  my $self = shift;
  $self->add_info(sprintf "vpo %s:%d is %s (%d connections to %d real ports)",
      $self->{snL4VirtualServerPortServerName},
      $self->{snL4VirtualServerPortPort},
      $self->{snL4VirtualServerPortAdminStatus},
      $self->{snL4VirtualServerPortStatisticCurrentConnection},
      scalar(@{$self->{ports}}));
  my $num_ports = scalar(@{$self->{ports}});
  my $active_ports = scalar(grep { $_->{snL4RealServerPortStatusState} eq 'active' } @{$self->{ports}});
  # snL4RealServerPortStatusState: failed wird auch angezeigt durch snL4RealServerStatusFailedPortExists => 1
  # wobei snL4RealServerStatusState' => serveractive ist
  # zu klaeren, ob ein kaputter real server auch in snL4RealServerPortStatusState angezeigt wird
  $self->{completeness} = $num_ports ? 100 * $active_ports / $num_ports : 0;
  if ($num_ports == 0) {
    $self->set_thresholds(warning => "0:", critical => "0:");
    $self->add_warning(sprintf "%s:%d has no bindings", 
      $self->{snL4VirtualServerPortServerName},
      $self->{snL4VirtualServerPortPort});
  } elsif ($active_ports == 1) {
    # only one member left = no more redundancy!!
    $self->set_thresholds(warning => "100:", critical => "51:");
  } else {
    $self->set_thresholds(warning => "51:", critical => "26:");
  }
  $self->add_message($self->check_thresholds($self->{completeness}));
  foreach (@{$self->{ports}}) {
    $_->check();
  }
  $self->add_perfdata(
      label => sprintf('pool_%s:%d_completeness', $self->{snL4VirtualServerPortServerName}, $self->{snL4VirtualServerPortPort}),
      value => $self->{completeness},
      uom => '%',
  );
  $self->add_perfdata(
      label => sprintf('pool_%s:%d_servercurconns', $self->{snL4VirtualServerPortServerName}, $self->{snL4VirtualServerPortPort}),
      value => $self->{snL4VirtualServerPortStatisticCurrentConnection},
      thresholds => 0,
  );
  if ($self->opts->report eq "html") {
    # tabelle mit snL4VirtualServerPortServerName:snL4VirtualServerPortPort
    $self->add_html("<table style=\"border-collapse:collapse; border: 1px solid black;\">");
    $self->add_html("<tr>");
    foreach (qw(Name Port Status Real Port Status Conn)) {
      $self->add_html(sprintf "<th style=\"text-align: left; padding-left: 4px; padding-right: 6px;\">%s</th>", $_);
    }
    $self->add_html("</tr>");
    foreach (sort {$a->{snL4RealServerPortStatusServerName} cmp $b->{snL4RealServerPortStatusServerName}} @{$self->{ports}}) {
      $self->add_html("<tr style=\"border: 1px solid black;\">");
      foreach my $attr (qw(snL4VirtualServerPortServerName snL4VirtualServerPortPort snL4VirtualServerPortAdminStatus)) {
        my $bgcolor = "#33ff00"; #green
        if ($self->{snL4VirtualServerPortAdminStatus} ne "enabled") {
          $bgcolor = "#acacac";
        } elsif ($self->check_messages()) {
          $bgcolor = "#f83838";
        }
        $self->add_html(sprintf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px; background-color: %s;\">%s</td>", $bgcolor, $self->{$attr});
      }
      foreach my $attr (qw(snL4RealServerPortStatusServerName snL4RealServerPortStatusPort snL4RealServerPortStatusState snL4RealServerPortStatusCurrentConnection)) {
        my $bgcolor = "#33ff00"; #green
        if ($self->{snL4VirtualServerPortAdminStatus} ne "enabled") {
          $bgcolor = "#acacac";
        } elsif ($_->{snL4RealServerPortStatusState} ne "active") {
          $bgcolor = "#f83838";
        }
        $self->add_html(sprintf "<td style=\"text-align: left; padding-left: 4px; padding-right: 6px; background-color: %s;\">%s</td>", $bgcolor, $_->{$attr});
      }
      $self->add_html("</tr>");
    }
    $self->add_html("</table>\n");
    $self->add_html("<!--\nASCII_NOTIFICATION_START\n");
    foreach (qw(Name Port Status Real Port Status Conn)) {
      $self->add_html(sprintf "%25s", $_);
    }
    $self->add_html("\n");
    foreach (sort {$a->{snL4RealServerPortStatusServerName} cmp $b->{snL4RealServerPortStatusServerName}} @{$self->{ports}}) {
      foreach my $attr (qw(snL4VirtualServerPortServerName snL4VirtualServerPortPort snL4VirtualServerPortAdminStatus)) {
        $self->add_html(sprintf "%25s", $self->{$attr});
      }
      foreach my $attr (qw(snL4RealServerPortStatusServerName snL4RealServerPortStatusPort snL4RealServerPortStatusState snL4RealServerPortStatusCurrentConnection)) {
        $self->add_html(sprintf "%15s", $_->{$attr});
      }
      $self->add_html("\n");
    }
    $self->add_html("ASCII_NOTIFICATION_END\n-->\n");
  }
}

sub add_port {
  my $self = shift;
  push(@{$self->{ports}}, shift);
}


package Classes::Foundry::Component::SLBSubsystem::RealServer;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  if ($self->{slbPoolMbrStatusEnabledState} eq "enabled") {
    if ($self->{slbPoolMbrStatusAvailState} ne "green") {
      $self->add_critical(sprintf
          "member %s is %s/%s (%s)",
          $self->{slbPoolMemberNodeName},
          $self->{slbPoolMemberMonitorState},
          $self->{slbPoolMbrStatusAvailState},
          $self->{slbPoolMbrStatusDetailReason});
    }
  }
}


package Classes::Foundry::Component::SLBSubsystem::RealServerPort;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub check {
  my $self = shift;
  my %params = @_;
  $self->add_info(sprintf "rpo %s:%d is %s",
      $self->{snL4RealServerPortStatusServerName},
      $self->{snL4RealServerPortStatusPort},
      $self->{snL4RealServerPortStatusState});
  $self->add_message($self->{snL4RealServerPortStatusState} eq 'active' ? OK : CRITICAL);
  # snL4VirtualServerPortStatisticTable dazumischen
  # snL4VirtualServerPortStatisticTable:   snL4VirtualServerPortStatisticCurrentConnection*
  # realports connecten und den status ermitteln
}


package Classes::Foundry::Component::SLBSubsystem::Binding;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

package Classes::Foundry::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('FOUNDRY-SN-AGENT-MIB', (qw(
      snAgGblDynMemUtil snAgGblDynMemTotal snAgGblDynMemFree)));
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{snAgGblDynMemUtil}) {
    $self->add_info(sprintf 'memory usage is %.2f%%',
        $self->{snAgGblDynMemUtil});
    $self->set_thresholds(warning => 80, critical => 99);
    $self->add_message($self->check_thresholds($self->{snAgGblDynMemUtil}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{snAgGblDynMemUtil},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

package Classes::Foundry::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FOUNDRY-SN-AGENT-MIB', [
      ['cpus', 'snAgentCpuUtilTable', 'Classes::Foundry::Component::CpuSubsystem::Cpu'],
  ]);
  $self->get_snmp_objects('FOUNDRY-SN-AGENT-MIB', (qw(
      snAgGblCpuUtil1SecAvg snAgGblCpuUtil5SecAvg snAgGblCpuUtil1MinAvg)));
}

sub check {
  my $self = shift;
  if (scalar (@{$self->{cpus}}) == 0) {
    $self->overall_check();
  } else {
    # snAgentCpuUtilInterval = 1, 5, 60, 300
    # --lookback can be one of these values, default is 300 (1,5 is a stupid choice)
    $self->opts->override_opt('lookback', 300) if ! $self->opts->lookback;
    foreach (grep { $_->{snAgentCpuUtilInterval} eq $self->opts->lookback} @{$self->{cpus}}) {
      $_->check();
    }
  }
}

sub dump {
  my $self = shift;
  $self->overall_dump();
  foreach (@{$self->{cpus}}) {
    $_->dump();
  }
}

sub overall_check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{snAgGblCpuUtil1MinAvg});
  $self->set_thresholds(warning => 50, critical => 90);
  $self->add_message($self->check_thresholds(
      $self->{snAgGblCpuUtil1MinAvg}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{snAgGblCpuUtil1MinAvg},
      uom => '%',
  );
}

sub overall_dump {
  my $self = shift;
  printf "[CPU]\n";
  foreach (qw(snAgGblCpuUtil1SecAvg snAgGblCpuUtil5SecAvg
      snAgGblCpuUtil1MinAvg)) {
    printf "%s: %s\n", $_, $self->{$_};
  }
  printf "\n";
}

sub unix_init {
  my $self = shift;
  my %params = @_;
  my $type = 0;
  $self->get_snmp_tables('UCD-SNMP-MIB', [
      ['loads', 'laTable', 'Classes::Foundry::Component::CpuSubsystem::Load'],
  ]);
}

sub unix_check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info('checking loads');
  foreach (@{$self->{loads}}) {
    $_->check();
  }
}

sub unix_dump {
  my $self = shift;
  foreach (@{$self->{loads}}) {
    $_->dump();
  }
}


package Classes::Foundry::Component::CpuSubsystem::Cpu;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  # newer mibs have snAgentCpuUtilPercent and snAgentCpuUtil100thPercent
  # snAgentCpuUtilValue is deprecated
  $self->{snAgentCpuUtilValue} = $self->{snAgentCpuUtil100thPercent} / 100
      if defined $self->{snAgentCpuUtil100thPercent};
  # if it is an old mib, watch out. snAgentCpuUtilValue is 100th of a percent
  # but it seems that sometimes in reality it is percent
  $self->{snAgentCpuUtilValue} = $self->{snAgentCpuUtilValue} / 100
      if $self->{snAgentCpuUtilValue} > 100;
  $self->add_info(sprintf 'cpu %s usage is %.2f', $self->{snAgentCpuUtilSlotNum}, $self->{snAgentCpuUtilValue});
  $self->set_thresholds(warning => 80, critical => 90);
  $self->add_message($self->check_thresholds($self->{snAgentCpuUtilValue}));
  $self->add_perfdata(
      label => 'cpu_'.$self->{snAgentCpuUtilSlotNum},
      value => $self->{snAgentCpuUtilValue},
      uom => '%',
  );
}


package Classes::Foundry::Component::CpuSubsystem::Load;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  my $errorfound = 0;
  $self->add_info(sprintf '%s is %.2f', lc $self->{laNames}, $self->{laLoadFloat});
  $self->set_thresholds(warning => $self->{laConfig},
      critical => $self->{laConfig});
  $self->add_message($self->check_thresholds($self->{laLoadFloat}));
  $self->add_perfdata(
      label => lc $self->{laNames},
      value => $self->{laLoadFloat},
  );
}

package Classes::Foundry::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->{powersupply_subsystem} =
      Classes::Foundry::Component::PowersupplySubsystem->new();
  $self->{fan_subsystem} =
      Classes::Foundry::Component::FanSubsystem->new();
  $self->{temperature_subsystem} =
      Classes::Foundry::Component::TemperatureSubsystem->new();
}

sub check {
  my $self = shift;
  $self->{powersupply_subsystem}->check();
  $self->{fan_subsystem}->check();
  $self->{temperature_subsystem}->check();
  if (! $self->check_messages()) {
    $self->add_ok("environmental hardware working fine");
  }
}

sub dump {
  my $self = shift;
  $self->{powersupply_subsystem}->dump();
  $self->{fan_subsystem}->dump();
  $self->{temperature_subsystem}->dump();
}


package Classes::Foundry::Component::PowersupplySubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FOUNDRY-SN-AGENT-MIB', [
      ['powersupplies', 'snChasPwrSupplyTable', 'Classes::Foundry::Component::PowersupplySubsystem::Powersupply'],
  ]);
}


package Classes::Foundry::Component::PowersupplySubsystem::Powersupply;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'powersupply %d is %s',
      $self->{snChasPwrSupplyIndex},
      $self->{snChasPwrSupplyOperStatus});
  if ($self->{snChasPwrSupplyOperStatus} eq 'failure') {
    $self->add_critical();
  }
}

package Classes::Foundry::Component::FanSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_tables('FOUNDRY-SN-AGENT-MIB', [
      ['fans', 'snChasFanTable', 'Classes::Foundry::Component::FanSubsystem::Fan'],
  ]);
}


package Classes::Foundry::Component::FanSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf 'fan %d is %s',
      $self->{snChasFanIndex},
      $self->{snChasFanOperStatus});
  if ($self->{snChasFanOperStatus} eq 'failure') {
    $self->add_critical();
  }
}

package Classes::Foundry::Component::TemperatureSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  my $temp = 0;
  $self->get_snmp_tables('FOUNDRY-SN-AGENT-MIB', [
      ['temperatures', 'snAgentTempTable', 'Classes::Foundry::Component::TemperatureSubsystem::Temperature'],
  ]);
  foreach(@{$self->{temperatures}}) {
    $_->{snAgentTempSlotNum} ||= $temp++;
    $_->{snAgentTempSensorId} ||= 1;
  }
}


package Classes::Foundry::Component::TemperatureSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->{snAgentTempValue} /= 2;
  $self->add_info(sprintf 'temperature %s is %.2fC', 
      $self->{snAgentTempSlotNum}, $self->{snAgentTempValue});
  $self->set_thresholds(warning => 60, critical => 70);
  $self->add_message($self->check_thresholds($self->{snAgentTempValue}));
  $self->add_perfdata(
      label => 'temperature_'.$self->{snAgentTempSlotNum},
      value => $self->{snAgentTempValue},
  );
}

package Classes::Foundry;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Foundry::Component::EnvironmentalSubsystem");
  } elsif ($self->mode =~ /device::hardware::load/) {
    $self->analyze_and_check_cpu_subsystem("Classes::Foundry::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::Foundry::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::lb/) {
    $self->analyze_and_check_slb_subsystem("Classes::Foundry::Component::SLBSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::PaloALto::Component::MemSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('NETSCREEN-RESOURCE-MIB', (qw(
      nsResMemAllocate nsResMemLeft nsResMemFrag)));
  my $mem_total = $self->{nsResMemAllocate} + $self->{nsResMemLeft};
  $self->{mem_usage} = $self->{nsResMemAllocate} / $mem_total * 100;
}

sub check {
  my $self = shift;
  $self->add_info('checking memory');
  if (defined $self->{mem_usage}) {
    $self->add_info(sprintf 'memory usage is %.2f%%', $self->{mem_usage});
    $self->set_thresholds(warning => 80,
        critical => 90);
    $self->add_message($self->check_thresholds($self->{mem_usage}));
    $self->add_perfdata(
        label => 'memory_usage',
        value => $self->{mem_usage},
        uom => '%',
    );
  } else {
    $self->add_unknown('cannot aquire memory usage');
  }
}

package Classes::PaloALto::Component::CpuSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('NETSCREEN-RESOURCE-MIB', (qw(
      nsResCpuAvg)));
}

sub check {
  my $self = shift;
  $self->add_info('checking cpus');
  $self->add_info(sprintf 'cpu usage is %.2f%%', $self->{nsResCpuAvg});
  $self->set_thresholds(warning => 50, critical => 90);
  $self->add_message($self->check_thresholds($self->{nsResCpuAvg}));
  $self->add_perfdata(
      label => 'cpu_usage',
      value => $self->{nsResCpuAvg},
      uom => '%',
  );
}


package Classes::PaloALto::Component::CpuSubsystem::Load;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf '%s is %.2f', lc $self->{laNames}, $self->{laLoadFloat});
  $self->set_thresholds(warning => $self->{laConfig},
      critical => $self->{laConfig});
  $self->add_message($self->check_thresholds($self->{laLoadFloat}));
  $self->add_perfdata(
      label => lc $self->{laNames},
      value => $self->{laLoadFloat},
  );
}

package Classes::PaloAlto::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
#######################
$self->no_such_mode();
die;
## entitymib, pan enhancement
  $self->get_snmp_objects("NETSCREEN-CHASSIS-MIB", (qw(
      sysBatteryStatus)));
  $self->get_snmp_tables("NETSCREEN-CHASSIS-MIB", [
      ['fans', 'nsFanTable', 'Classes::PaloAlto::Component::EnvironmentalSubsystem::Fan'],
      ['power', 'nsPowerTable', 'Classes::PaloAlto::Component::EnvironmentalSubsystem::Power'],
      ['slots', 'nsSlotTable', 'Classes::PaloAlto::Component::EnvironmentalSubsystem::Slot'],
      ['temperatures', 'nsTemperatureTable', 'Classes::PaloAlto::Component::EnvironmentalSubsystem::Temperature'],
  ]);
}

sub check {
  my $self = shift;
  foreach (@{$self->{fans}}, @{$self->{power}}, @{$self->{slots}}, @{$self->{temperatures}}) {
    $_->check();
  }
}


package Classes::PaloAlto::Component::EnvironmentalSubsystem::Fan;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "fan %s (%s) is %s",
      $self->{nsFanId}, $self->{nsFanDesc}, $self->{nsFanStatus});
  if ($self->{nsFanStatus} eq "notInstalled") {
  } elsif ($self->{nsFanStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsFanStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::PaloAlto::Component::EnvironmentalSubsystem::Power;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "power supply %s (%s) is %s",
      $self->{nsPowerId}, $self->{nsPowerDesc}, $self->{nsPowerStatus});
  if ($self->{nsPowerStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsPowerStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::PaloAlto::Component::EnvironmentalSubsystem::Slot;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "%s slot %s (%s) is %s",
      $self->{nsSlotType}, $self->{nsSlotId}, $self->{nsSlotSN}, $self->{nsSlotStatus});
  if ($self->{nsSlotStatus} eq "good") {
    $self->add_ok();
  } elsif ($self->{nsSlotStatus} eq "fail") {
    $self->add_warning();
  }
}


package Classes::PaloAlto::Component::EnvironmentalSubsystem::Temperature;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub check {
  my $self = shift;
  $self->add_info(sprintf "temperature %s is %sC",
      $self->{nsTemperatureId}, $self->{nsTemperatureDesc}, $self->{nsTemperatureCur});
  $self->add_ok();
  $self->add_perfdata(
      label => 'temp_'.$self->{nsTemperatureId},
      value => $self->{nsTemperatureCur},
  );
}

package Classes::PaloAlto::Component::HaSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;
use constant { OK => 0, WARNING => 1, CRITICAL => 2, UNKNOWN => 3 };

sub init {
  my $self = shift;
  if ($self->mode =~ /device::ha::role/) {
  $self->get_snmp_objects('PAN-COMMON-MIB', (qw(
      panSysHAMode panSysHAState panSysHAPeerState)));
    if (! $self->opts->role()) {
      $self->opts->override_opt('role', 'active');
    }
  }
}

sub check {
  my $self = shift;
  $self->add_info('checking ha');
  $self->add_info(sprintf 'ha mode is %s, state is %s, peer state is %s', 
      $self->{panSysHAMode},
      $self->{panSysHAState},
      $self->{panSysHAPeerState},
  );
  if ($self->{panSysHAMode} eq 'disabled') {
    $self->add_message(
        defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
        'ha was not started');
  } else {
    if ($self->{panSysHAState} ne $self->opts->role()) {
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
          $self->{info});
      $self->add_message(
          defined $self->opts->mitigation() ? $self->opts->mitigation() : WARNING,
          sprintf "expected role %s", $self->opts->role())
    } else {
      $self->add_ok();
    }
  }
}

package Classes::PaloAlto;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::ENTITYSENSORMIB::Component::EnvironmentalSubsystem");
    $self->analyze_and_check_environmental_subsystem("Classes::HOSTRESOURCESMIB::Component::EnvironmentalSubsystem");
    # entity-state-mib gibts u.u. auch
    # The entStateTable will have entries for Line Cards, Fan Trays and Power supplies. Since these entities only apply to chassis systems, only PA-7000 series devices will support this MIB.
    # gibts aber erst, wenn einer die entwicklung zahlt. bis dahin ist es
    # mir scheissegal, wenn euch die firewalls abkacken, ihr freibiervisagen
  } elsif ($self->mode =~ /device::hardware::load/) {
    # CPU util on management plane
    # Utilization of CPUs on dataplane that are used for system functions
    $self->analyze_and_check_cpu_subsystem("Classes::HOSTRESOURCESMIB::Component::CpuSubsystem");
  } elsif ($self->mode =~ /device::hardware::memory/) {
    $self->analyze_and_check_mem_subsystem("Classes::HOSTRESOURCESMIB::Component::MemSubsystem");
  } elsif ($self->mode =~ /device::ha::/) {
    $self->analyze_and_check_ha_subsystem("Classes::PaloAlto::Component::HaSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Bluecoat;
our @ISA = qw(Classes::Device);
use strict;

use constant trees => (
  '1.3.6.1.2.1.1', # RFC1213-MIB
  '1.3.6.1.2.1.10.33', # RS-232-MIB
  '1.3.6.1.2.1.22.1.1', # SNMP-REPEATER-MIB
  '1.3.6.1.2.1.25.1', # HOST-RESOURCES-MIB
  '1.3.6.1.2.1.30', # IANAifType-MIB
  '1.3.6.1.2.1.31', # IF-MIB
  '1.3.6.1.2.1.65', # WWW-MIB
  '1.3.6.1.3.25.17', # PROXY-MIB
  '1.3.6.1.4.1.3417', # BLUECOAT-MIB
  '1.3.6.1.4.1.3417', # BLUECOAT-MIB
  '1.3.6.1.4.1.3417', # BLUECOAT-MIB
  '1.3.6.1.4.1.3417.2.1', # SENSOR-MIB
  '1.3.6.1.4.1.3417.2.10', # BLUECOAT-AV-MIB
  '1.3.6.1.4.1.3417.2.2', # DISK-MIB
  '1.3.6.1.4.1.3417.2.3', # ATTACK-MIB
  '1.3.6.1.4.1.3417.2.4', # USAGE-MIB
  '1.3.6.1.4.1.3417.2.5', # WCCP-MIB
  '1.3.6.1.4.1.3417.2.6', # POLICY-MIB
  '1.3.6.1.4.1.3417.2.8', # SYSTEM-RESOURCES-MIB
  '1.3.6.1.4.1.3417.2.9', # BLUECOAT-HOST-RESOURCES-MIB
  '1.3.6.1.4.1.99.12.33', # SR-COMMUNITY-MIB
  '1.3.6.1.4.1.99.12.35', # USM-TARGET-TAG-MIB
  '1.3.6.1.4.1.99.12.36', # TGT-ADDRESS-MASK-MIB
  '1.3.6.1.4.1.99.42', # MLM-MIB
  '1.3.6.1.6.3.1', # SNMPv2-MIB
  '1.3.6.1.6.3.10', # SNMP-FRAMEWORK-MIB
  '1.3.6.1.6.3.11', # SNMP-MPD-MIB
  '1.3.6.1.6.3.1133', # COMMUNITY-MIB
  '1.3.6.1.6.3.1134', # V2ADMIN-MIB
  '1.3.6.1.6.3.1135', # USEC-MIB
  '1.3.6.1.6.3.12', # SNMP-TARGET-MIB
  '1.3.6.1.6.3.13', # SNMP-NOTIFICATION-MIB
  '1.3.6.1.6.3.14', # SNMP-PROXY-MIB
  '1.3.6.1.6.3.15', # SNMP-USER-BASED-SM-MIB
  '1.3.6.1.6.3.16', # SNMP-VIEW-BASED-ACM-MIB
  '1.3.6.1.6.3.18', # SNMP-COMMUNITY-MIB
);

sub init {
  my $self = shift;
  if ($self->{productname} =~ /Blue.*Coat.*SG\d+/i) {
    # product ProxySG  Blue Coat SG600
    # iso.3.6.1.4.1.3417.2.11.1.3.0 = STRING: "Version: SGOS 5.5.8.1, Release id: 78642 Proxy Edition"
    bless $self, 'Classes::SGOS';
    $self->debug('using Classes::SGOS');
  } elsif ($self->{productname} =~ /Blue.*Coat.*AV\d+/i) {
    # product Blue Coat AV510 Series, ProxyAV Version: 3.5.1.1, Release id: 111017
    bless $self, 'Classes::AVOS';
    $self->debug('using Classes::AVOS');
  }
  if (ref($self) ne "Classes::Bluecoat") {
    $self->init();
  }
}

package Classes::Cumulus;
our @ISA = qw(Classes::Device);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::LMSENSORSMIB::Component::EnvironmentalSubsystem");
  } else {
    $self->no_such_mode();
  }
}

package Classes::Netgear;
our @ISA = qw(Classes::Device);
use strict;


sub init {
  my $self = shift;
  # netgear does not publish mibs
  $self->no_such_mode();
}

package Classes::Lantronix;
our @ISA = qw(Classes::Device);
use strict;
package Classes::Lantronix::SLS;
our @ISA = qw(Classes::Lantronix);
use strict;

sub init {
  my $self = shift;
  if ($self->mode =~ /device::hardware::health/) {
    $self->analyze_and_check_environmental_subsystem("Classes::Lantronix::SLS::Component::EnvironmentalSubsystem");
  } else {
    $self->no_such_mode();
  }
}


package Classes::Lantronix::SLS::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my $self = shift;
  $self->get_snmp_objects('LARA-MIB', qw(checkHostPower));
}

sub check {
  my $self = shift;
  $self->add_info(sprintf 'host power status is %s', $self->{checkHostPower});
  if ($self->{checkHostPower} eq 'hasPower') {
    $self->add_ok();
  } else {
    $self->add_critical();
  }
}

{
  no warnings qw(once);
  $Monitoring::GLPlugin::SNMP::discover_ids = {};
  $Monitoring::GLPlugin::SNMP::mib_ids = {};
  $Monitoring::GLPlugin::SNMP::mibs_and_oids = {};
  $Monitoring::GLPlugin::SNMP::definitions = {};
}

$Monitoring::GLPlugin::SNMP::discover_ids = {
  '1.3.6.1.4.1.12532.252.5.1' => 'Classes::Juniper::IVE',
  '1.3.6.1.4.1.9.1.1348' => 'Classes::CiscoCCM',
  '1.3.6.1.4.1.9.1.746' => 'Classes::CiscoCCM',
  '1.3.6.1.4.1.244.1.11' => 'Classes::Lantronix::SLS',
};

$Monitoring::GLPlugin::SNMP::mib_ids = {
  'SW-MIB' => '1.3.6.1.4.1.1588.2.1.1.1',
  'NETSCREEN-PRODUCTS-MIB' => '1.3.6.1.4.1.3224.1',
  'HOST-RESOURCES-MIB' => '1.3.6.1.2.1.25',
  'CISCO-ENTITY-SENSOR-MIB' => '1.3.6.1.4.1.9.9.91',
  'CISCO-ENTITY-FRU-CONTROL-MIB' => '1.3.6.1.4.1.9.9.117.1',
  'CISCO-ENTITY-ALARM-MIB' => '1.3.6.1.4.1.9.9.138.1',
  'CISCO-ENVMON-MIB' => '1.3.6.1.4.1.9.9.13',
  'PAN-PRODUCTS-MIB' => '1.3.6.1.4.1.25461.2.3',
  'NETGEAR-MIB' => '1.3.6.1.4.1.4526',
  'IP-FORWARD-MIB' => '1.3.6.1.2.1.4.24',
  'RAPID-CITY-MIB' => '1.3.6.1.4.1.2272',
  'S5-CHASSIS-MIB' => '1.3.6.1.4.1.45.1.6.3',
};

$Monitoring::GLPlugin::SNMP::mibs_and_oids = {
  'MIB-II' => {
      sysDescr => '1.3.6.1.2.1.1.1',
      sysObjectID => '1.3.6.1.2.1.1.2',
      sysUpTime => '1.3.6.1.2.1.1.3',
      sysName => '1.3.6.1.2.1.1.5',
  },
  'MINI-IFMIB' => {
      ifNumber => '1.3.6.1.2.1.2.1',
      ifTableLastChange => '1.3.6.1.2.1.31.1.5',
      ifTable => '1.3.6.1.2.1.2.2',
      ifEntry => '1.3.6.1.2.1.2.2.1',
      ifIndex => '1.3.6.1.2.1.2.2.1.1',
      ifDescr => '1.3.6.1.2.1.2.2.1.2',
      ifXTable => '1.3.6.1.2.1.31.1.1',
      ifXEntry => '1.3.6.1.2.1.31.1.1.1',
      ifName => '1.3.6.1.2.1.31.1.1.1.1',
      ifAlias => '1.3.6.1.2.1.31.1.1.1.18',
  },
  'IFMIB' => {
      ifNumber => '1.3.6.1.2.1.2.1',
      ifTableLastChange => '1.3.6.1.2.1.31.1.5',
      ifTable => '1.3.6.1.2.1.2.2',
      ifEntry => '1.3.6.1.2.1.2.2.1',
      ifIndex => '1.3.6.1.2.1.2.2.1.1',
      ifDescr => '1.3.6.1.2.1.2.2.1.2',
      ifType => '1.3.6.1.2.1.2.2.1.3',
      ifTypeDefinition => 'IFMIB::ifType',
      ifMtu => '1.3.6.1.2.1.2.2.1.4',
      ifSpeed => '1.3.6.1.2.1.2.2.1.5',
      ifPhysAddress => '1.3.6.1.2.1.2.2.1.6',
      ifAdminStatus => '1.3.6.1.2.1.2.2.1.7',
      ifOperStatus => '1.3.6.1.2.1.2.2.1.8',
      ifLastChange => '1.3.6.1.2.1.2.2.1.9',
      ifInOctets => '1.3.6.1.2.1.2.2.1.10',
      ifInUcastPkts => '1.3.6.1.2.1.2.2.1.11',
      ifInNUcastPkts => '1.3.6.1.2.1.2.2.1.12',
      ifInDiscards => '1.3.6.1.2.1.2.2.1.13',
      ifInErrors => '1.3.6.1.2.1.2.2.1.14',
      ifInUnknownProtos => '1.3.6.1.2.1.2.2.1.15',
      ifOutOctets => '1.3.6.1.2.1.2.2.1.16',
      ifOutUcastPkts => '1.3.6.1.2.1.2.2.1.17',
      ifOutNUcastPkts => '1.3.6.1.2.1.2.2.1.18',
      ifOutDiscards => '1.3.6.1.2.1.2.2.1.19',
      ifOutErrors => '1.3.6.1.2.1.2.2.1.20',
      ifOutQLen => '1.3.6.1.2.1.2.2.1.21',
      ifSpecific => '1.3.6.1.2.1.2.2.1.22',
      ifAdminStatusDefinition => {
          1 => 'up',
          2 => 'down',
          3 => 'testing',
      },
      ifOperStatusDefinition => {
          1 => 'up',
          2 => 'down',
          3 => 'testing',
          4 => 'unknown',
          5 => 'dormant',
          6 => 'notPresent',
          7 => 'lowerLayerDown',
      },
      # INDEX { ifIndex }
      #
      ifXTable => '1.3.6.1.2.1.31.1.1',
      ifXEntry => '1.3.6.1.2.1.31.1.1.1',
      ifName => '1.3.6.1.2.1.31.1.1.1.1',
      ifInMulticastPkts => '1.3.6.1.2.1.31.1.1.1.2',
      ifInBroadcastPkts => '1.3.6.1.2.1.31.1.1.1.3',
      ifOutMulticastPkts => '1.3.6.1.2.1.31.1.1.1.4',
      ifOutBroadcastPkts => '1.3.6.1.2.1.31.1.1.1.5',
      ifHCInOctets => '1.3.6.1.2.1.31.1.1.1.6',
      ifHCInUcastPkts => '1.3.6.1.2.1.31.1.1.1.7',
      ifHCInMulticastPkts => '1.3.6.1.2.1.31.1.1.1.8',
      ifHCInBroadcastPkts => '1.3.6.1.2.1.31.1.1.1.9',
      ifHCOutOctets => '1.3.6.1.2.1.31.1.1.1.10',
      ifHCOutUcastPkts => '1.3.6.1.2.1.31.1.1.1.11',
      ifHCOutMulticastPkts => '1.3.6.1.2.1.31.1.1.1.12',
      ifHCOutBroadcastPkts => '1.3.6.1.2.1.31.1.1.1.13',
      ifLinkUpDownTrapEnable => '1.3.6.1.2.1.31.1.1.1.14',
      ifHighSpeed => '1.3.6.1.2.1.31.1.1.1.15',
      ifPromiscuousMode => '1.3.6.1.2.1.31.1.1.1.16',
      ifConnectorPresent => '1.3.6.1.2.1.31.1.1.1.17',
      ifAlias => '1.3.6.1.2.1.31.1.1.1.18',
      ifCounterDiscontinuityTime => '1.3.6.1.2.1.31.1.1.1.19',
      ifLinkUpDownTrapEnableDefinition => {
          1 => 'enabled',
          2 => 'disabled',
      },
      # ifXEntry AUGMENTS ifEntry
      #
  },
  'IP-MIB' => {
    ip => '1.3.6.1.2.1.4',
    ipForwarding => '1.3.6.1.2.1.4.1',
    ipDefaultTTL => '1.3.6.1.2.1.4.2',
    ipInReceives => '1.3.6.1.2.1.4.3',
    ipInHdrErrors => '1.3.6.1.2.1.4.4',
    ipInAddrErrors => '1.3.6.1.2.1.4.5',
    ipForwDatagrams => '1.3.6.1.2.1.4.6',
    ipInUnknownProtos => '1.3.6.1.2.1.4.7',
    ipInDiscards => '1.3.6.1.2.1.4.8',
    ipInDelivers => '1.3.6.1.2.1.4.9',
    ipOutRequests => '1.3.6.1.2.1.4.10',
    ipOutDiscards => '1.3.6.1.2.1.4.11',
    ipOutNoRoutes => '1.3.6.1.2.1.4.12',
    ipReasmTimeout => '1.3.6.1.2.1.4.13',
    ipReasmReqds => '1.3.6.1.2.1.4.14',
    ipReasmOKs => '1.3.6.1.2.1.4.15',
    ipReasmFails => '1.3.6.1.2.1.4.16',
    ipFragOKs => '1.3.6.1.2.1.4.17',
    ipFragFails => '1.3.6.1.2.1.4.18',
    ipFragCreates => '1.3.6.1.2.1.4.19',
    ipAddrTable => '1.3.6.1.2.1.4.20',
    ipAddrEntry => '1.3.6.1.2.1.4.20.1',
    ipAdEntAddr => '1.3.6.1.2.1.4.20.1.1',
    ipAdEntIfIndex => '1.3.6.1.2.1.4.20.1.2',
    ipAdEntNetMask => '1.3.6.1.2.1.4.20.1.3',
    ipAdEntBcastAddr => '1.3.6.1.2.1.4.20.1.4',
    ipAdEntReasmMaxSize => '1.3.6.1.2.1.4.20.1.5',
    ipRouteTable => '1.3.6.1.2.1.4.21',
    ipRouteEntry => '1.3.6.1.2.1.4.21.1',
    ipRouteDest => '1.3.6.1.2.1.4.21.1.1',
    ipRouteIfIndex => '1.3.6.1.2.1.4.21.1.2',
    ipRouteMetric1 => '1.3.6.1.2.1.4.21.1.3',
    ipRouteMetric2 => '1.3.6.1.2.1.4.21.1.4',
    ipRouteMetric3 => '1.3.6.1.2.1.4.21.1.5',
    ipRouteMetric4 => '1.3.6.1.2.1.4.21.1.6',
    ipRouteNextHop => '1.3.6.1.2.1.4.21.1.7',
    ipRouteType => '1.3.6.1.2.1.4.21.1.8',
    ipRouteProto => '1.3.6.1.2.1.4.21.1.9',
    ipRouteAge => '1.3.6.1.2.1.4.21.1.10',
    ipRouteMask => '1.3.6.1.2.1.4.21.1.11',
    ipRouteMetric5 => '1.3.6.1.2.1.4.21.1.12',
    ipRouteInfo => '1.3.6.1.2.1.4.21.1.13',
    ipNetToMediaTable => '1.3.6.1.2.1.4.22',
    ipNetToMediaEntry => '1.3.6.1.2.1.4.22.1',
    ipNetToMediaIfIndex => '1.3.6.1.2.1.4.22.1.1',
    ipNetToMediaPhysAddress => '1.3.6.1.2.1.4.22.1.2',
    ipNetToMediaNetAddress => '1.3.6.1.2.1.4.22.1.3',
    ipNetToMediaType => '1.3.6.1.2.1.4.22.1.4',
    ipRoutingDiscards => '1.3.6.1.2.1.4.23',
    icmp => '1.3.6.1.2.1.5',
    icmp => '1.3.6.1.2.1.5',
    icmpInMsgs => '1.3.6.1.2.1.5.1',
    icmpInErrors => '1.3.6.1.2.1.5.2',
    icmpInDestUnreachs => '1.3.6.1.2.1.5.3',
    icmpInTimeExcds => '1.3.6.1.2.1.5.4',
    icmpInParmProbs => '1.3.6.1.2.1.5.5',
    icmpInSrcQuenchs => '1.3.6.1.2.1.5.6',
    icmpInRedirects => '1.3.6.1.2.1.5.7',
    icmpInEchos => '1.3.6.1.2.1.5.8',
    icmpInEchoReps => '1.3.6.1.2.1.5.9',
    icmpInTimestamps => '1.3.6.1.2.1.5.10',
    icmpInTimestampReps => '1.3.6.1.2.1.5.11',
    icmpInAddrMasks => '1.3.6.1.2.1.5.12',
    icmpInAddrMaskReps => '1.3.6.1.2.1.5.13',
    icmpOutMsgs => '1.3.6.1.2.1.5.14',
    icmpOutErrors => '1.3.6.1.2.1.5.15',
    icmpOutDestUnreachs => '1.3.6.1.2.1.5.16',
    icmpOutTimeExcds => '1.3.6.1.2.1.5.17',
    icmpOutParmProbs => '1.3.6.1.2.1.5.18',
    icmpOutSrcQuenchs => '1.3.6.1.2.1.5.19',
    icmpOutRedirects => '1.3.6.1.2.1.5.20',
    icmpOutEchos => '1.3.6.1.2.1.5.21',
    icmpOutEchoReps => '1.3.6.1.2.1.5.22',
    icmpOutTimestamps => '1.3.6.1.2.1.5.23',
    icmpOutTimestampReps => '1.3.6.1.2.1.5.24',
    icmpOutAddrMasks => '1.3.6.1.2.1.5.25',
    icmpOutAddrMaskReps => '1.3.6.1.2.1.5.26',
    ipMIBConformance => '1.3.6.1.2.1.48.2',
    ipMIBCompliances => '1.3.6.1.2.1.48.2.1',
    ipMIBGroups => '1.3.6.1.2.1.48.2.2',
  },
  'IP-FORWARD-MIB' => {
    ipForward => '1.3.6.1.2.1.4.24',
    inetCidrRouteNumber => '1.3.6.1.2.1.4.24.6.0',
    inetCidrRouteDiscards => '1.3.6.1.2.1.4.24.8.0',
    inetCidrRouteTable => '1.3.6.1.2.1.4.24.7',
    inetCidrRouteEntry => '1.3.6.1.2.1.4.24.7.1',
    inetCidrRouteDestType => '1.3.6.1.2.1.4.24.7.1.1',
    inetCidrRouteDest => '1.3.6.1.2.1.4.24.7.1.2',
    inetCidrRoutePfxLen => '1.3.6.1.2.1.4.24.7.1.3',
    inetCidrRoutePolicy => '1.3.6.1.2.1.4.24.7.1.4',
    inetCidrRouteNextHopType => '1.3.6.1.2.1.4.24.7.1.5',
    inetCidrRouteNextHop => '1.3.6.1.2.1.4.24.7.1.6',
    inetCidrRouteIfIndex => '1.3.6.1.2.1.4.24.7.1.7',
    inetCidrRouteType => '1.3.6.1.2.1.4.24.7.1.8',
    inetCidrRouteProto => '1.3.6.1.2.1.4.24.7.1.9',
    inetCidrRouteAge => '1.3.6.1.2.1.4.24.7.1.10',
    inetCidrRouteNextHopAS => '1.3.6.1.2.1.4.24.7.1.11',
    inetCidrRouteMetric1 => '1.3.6.1.2.1.4.24.7.1.12',
    inetCidrRouteMetric2 => '1.3.6.1.2.1.4.24.7.1.13',
    inetCidrRouteMetric3 => '1.3.6.1.2.1.4.24.7.1.14',
    inetCidrRouteMetric4 => '1.3.6.1.2.1.4.24.7.1.15',
    inetCidrRouteMetric5 => '1.3.6.1.2.1.4.24.7.1.16',
    inetCidrRouteStatus => '1.3.6.1.2.1.4.24.7.1.17',
    ipForwardConformance => '1.3.6.1.2.1.4.24.5',
    ipForwardGroups => '1.3.6.1.2.1.4.24.5.1',
    ipForwardCompliances => '1.3.6.1.2.1.4.24.5.2',
    ipForward => '1.3.6.1.2.1.4.24',
    ipCidrRouteNumber => '1.3.6.1.2.1.4.24.3.0',
    ipCidrRouteTable => '1.3.6.1.2.1.4.24.4',
    ipCidrRouteEntry => '1.3.6.1.2.1.4.24.4.1',
    ipCidrRouteDest => '1.3.6.1.2.1.4.24.4.1.1',
    ipCidrRouteMask => '1.3.6.1.2.1.4.24.4.1.2',
    ipCidrRouteTos => '1.3.6.1.2.1.4.24.4.1.3',
    ipCidrRouteNextHop => '1.3.6.1.2.1.4.24.4.1.4',
    ipCidrRouteIfIndex => '1.3.6.1.2.1.4.24.4.1.5',
    ipCidrRouteType => '1.3.6.1.2.1.4.24.4.1.6',
    ipCidrRouteTypeDefinition => {
      1 => 'other',
      2 => 'reject',
      3 => 'local',
      4 => 'remote',
    },
    ipCidrRouteProto => '1.3.6.1.2.1.4.24.4.1.7',
    ipCidrRouteProtoDefinition => {
      1 => 'other',
      2 => 'local',
      3 => 'netmgmt',
      4 => 'icmp',
      5 => 'egp',
      6 => 'ggp',
      7 => 'hello',
      8 => 'rip',
      9 => 'isIs',
      10 => 'esIs',
      11 => 'ciscoIgrp',
      12 => 'bbnSpfIgp',
      13 => 'ospf',
      14 => 'bgp',
      15 => 'idpr',
      16 => 'ciscoEigrp',
    },
    ipCidrRouteAge => '1.3.6.1.2.1.4.24.4.1.8',
    ipCidrRouteInfo => '1.3.6.1.2.1.4.24.4.1.9',
    ipCidrRouteNextHopAS => '1.3.6.1.2.1.4.24.4.1.10',
    ipCidrRouteMetric1 => '1.3.6.1.2.1.4.24.4.1.11',
    ipCidrRouteMetric2 => '1.3.6.1.2.1.4.24.4.1.12',
    ipCidrRouteMetric3 => '1.3.6.1.2.1.4.24.4.1.13',
    ipCidrRouteMetric4 => '1.3.6.1.2.1.4.24.4.1.14',
    ipCidrRouteMetric5 => '1.3.6.1.2.1.4.24.4.1.15',
    ipCidrRouteStatus => '1.3.6.1.2.1.4.24.4.1.16',
    ipCidrRouteStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ipForward => '1.3.6.1.2.1.4.24',
    ipForwardNumber => '1.3.6.1.2.1.4.24.1.0',
    ipForwardTable => '1.3.6.1.2.1.4.24.2',
    ipForwardEntry => '1.3.6.1.2.1.4.24.2.1',
    ipForwardDest => '1.3.6.1.2.1.4.24.2.1.1',
    ipForwardMask => '1.3.6.1.2.1.4.24.2.1.2',
    ipForwardPolicy => '1.3.6.1.2.1.4.24.2.1.3',
    ipForwardNextHop => '1.3.6.1.2.1.4.24.2.1.4',
    ipForwardIfIndex => '1.3.6.1.2.1.4.24.2.1.5',
    ipForwardType => '1.3.6.1.2.1.4.24.2.1.6',
    ipForwardProto => '1.3.6.1.2.1.4.24.2.1.7',
    ipForwardAge => '1.3.6.1.2.1.4.24.2.1.8',
    ipForwardInfo => '1.3.6.1.2.1.4.24.2.1.9',
    ipForwardNextHopAS => '1.3.6.1.2.1.4.24.2.1.10',
    ipForwardMetric1 => '1.3.6.1.2.1.4.24.2.1.11',
    ipForwardMetric2 => '1.3.6.1.2.1.4.24.2.1.12',
    ipForwardMetric3 => '1.3.6.1.2.1.4.24.2.1.13',
    ipForwardMetric4 => '1.3.6.1.2.1.4.24.2.1.14',
    ipForwardMetric5 => '1.3.6.1.2.1.4.24.2.1.15',
  },
  'HOST-RESOURCES-MIB' => {
      host => '1.3.6.1.2.1.25',
      hrSystem => '1.3.6.1.2.1.25.1',
      hrStorage => '1.3.6.1.2.1.25.2',
      hrDevice => '1.3.6.1.2.1.25.3',
      hrSWRun => '1.3.6.1.2.1.25.4',
      hrSWRunPerf => '1.3.6.1.2.1.25.5',
      hrSWInstalled => '1.3.6.1.2.1.25.6',
      hrFSTypes => '1.3.6.1.2.1.25.3.9',
      hrFSOther => '1.3.6.1.2.1.25.3.9.1',
      hrFSUnknown => '1.3.6.1.2.1.25.3.9.2',
      hrFSBerkeleyFFS => '1.3.6.1.2.1.25.3.9.3',
      hrFSSys5FS => '1.3.6.1.2.1.25.3.9.4',
      hrFSFat => '1.3.6.1.2.1.25.3.9.5',
      hrFSHPFS => '1.3.6.1.2.1.25.3.9.6',
      hrFSHFS => '1.3.6.1.2.1.25.3.9.7',
      hrFSMFS => '1.3.6.1.2.1.25.3.9.8',
      hrFSNTFS => '1.3.6.1.2.1.25.3.9.9',
      hrFSVNode => '1.3.6.1.2.1.25.3.9.10',
      hrFSJournaled => '1.3.6.1.2.1.25.3.9.11',
      hrFSiso9660 => '1.3.6.1.2.1.25.3.9.12',
      hrFSRockRidge => '1.3.6.1.2.1.25.3.9.13',
      hrFSNFS => '1.3.6.1.2.1.25.3.9.14',
      hrFSNetware => '1.3.6.1.2.1.25.3.9.15',
      hrFSAFS => '1.3.6.1.2.1.25.3.9.16',
      hrFSDFS => '1.3.6.1.2.1.25.3.9.17',
      hrFSAppleshare => '1.3.6.1.2.1.25.3.9.18',
      hrFSRFS => '1.3.6.1.2.1.25.3.9.19',
      hrFSDGCFS => '1.3.6.1.2.1.25.3.9.20',
      hrFSBFS => '1.3.6.1.2.1.25.3.9.21',
      hrSystem => '1.3.6.1.2.1.25.1',
      hrSystemUptime => '1.3.6.1.2.1.25.1.1.0',
      hrSystemDate => '1.3.6.1.2.1.25.1.2.0',
      hrSystemInitialLoadDevice => '1.3.6.1.2.1.25.1.3.0',
      hrSystemInitialLoadParameters => '1.3.6.1.2.1.25.1.4.0',
      hrSystemNumUsers => '1.3.6.1.2.1.25.1.5.0',
      hrSystemProcesses => '1.3.6.1.2.1.25.1.6.0',
      hrSystemMaxProcesses => '1.3.6.1.2.1.25.1.7.0',
      hrStorageTypes => '1.3.6.1.2.1.25.2.1',
      hrStorageOther => '1.3.6.1.2.1.25.2.1.1',
      hrStorageRam => '1.3.6.1.2.1.25.2.1.2',
      hrStorageVirtualMemory => '1.3.6.1.2.1.25.2.1.3',
      hrStorageFixedDisk => '1.3.6.1.2.1.25.2.1.4',
      hrStorageRemovableDisk => '1.3.6.1.2.1.25.2.1.5',
      hrStorageFloppyDisk => '1.3.6.1.2.1.25.2.1.6',
      hrStorageCompactDisc => '1.3.6.1.2.1.25.2.1.7',
      hrStorageRamDisk => '1.3.6.1.2.1.25.2.1.8',
      hrStorage => '1.3.6.1.2.1.25.2',
      hrMemorySize => '1.3.6.1.2.1.25.2.2.0',
      hrStorageTable => '1.3.6.1.2.1.25.2.3',
      hrStorageEntry => '1.3.6.1.2.1.25.2.3.1',
      hrStorageIndex => '1.3.6.1.2.1.25.2.3.1.1',
      hrStorageType => '1.3.6.1.2.1.25.2.3.1.2',
      hrStorageTypeDefinition => 'OID::HOST-RESOURCES-MIB',
      hrStorageDescr => '1.3.6.1.2.1.25.2.3.1.3',
      hrStorageAllocationUnits => '1.3.6.1.2.1.25.2.3.1.4',
      hrStorageSize => '1.3.6.1.2.1.25.2.3.1.5',
      hrStorageUsed => '1.3.6.1.2.1.25.2.3.1.6',
      hrStorageAllocationFailures => '1.3.6.1.2.1.25.2.3.1.7',
      hrDeviceTypes => '1.3.6.1.2.1.25.3.1',
      hrDeviceOther => '1.3.6.1.2.1.25.3.1.1',
      hrDeviceUnknown => '1.3.6.1.2.1.25.3.1.2',
      hrDeviceProcessor => '1.3.6.1.2.1.25.3.1.3',
      hrDeviceNetwork => '1.3.6.1.2.1.25.3.1.4',
      hrDevicePrinter => '1.3.6.1.2.1.25.3.1.5',
      hrDeviceDiskStorage => '1.3.6.1.2.1.25.3.1.6',
      hrDeviceVideo => '1.3.6.1.2.1.25.3.1.10',
      hrDeviceAudio => '1.3.6.1.2.1.25.3.1.11',
      hrDeviceCoprocessor => '1.3.6.1.2.1.25.3.1.12',
      hrDeviceKeyboard => '1.3.6.1.2.1.25.3.1.13',
      hrDeviceModem => '1.3.6.1.2.1.25.3.1.14',
      hrDeviceParallelPort => '1.3.6.1.2.1.25.3.1.15',
      hrDevicePointing => '1.3.6.1.2.1.25.3.1.16',
      hrDeviceSerialPort => '1.3.6.1.2.1.25.3.1.17',
      hrDeviceTape => '1.3.6.1.2.1.25.3.1.18',
      hrDeviceClock => '1.3.6.1.2.1.25.3.1.19',
      hrDeviceVolatileMemory => '1.3.6.1.2.1.25.3.1.20',
      hrDeviceNonVolatileMemory => '1.3.6.1.2.1.25.3.1.21',
      hrDevice => '1.3.6.1.2.1.25.3',
      hrDeviceTable => '1.3.6.1.2.1.25.3.2',
      hrDeviceEntry => '1.3.6.1.2.1.25.3.2.1',
      hrDeviceIndex => '1.3.6.1.2.1.25.3.2.1.1',
      hrDeviceType => '1.3.6.1.2.1.25.3.2.1.2',
      hrDeviceDescr => '1.3.6.1.2.1.25.3.2.1.3',
      hrDeviceID => '1.3.6.1.2.1.25.3.2.1.4',
      hrDeviceStatus => '1.3.6.1.2.1.25.3.2.1.5',
      hrDeviceErrors => '1.3.6.1.2.1.25.3.2.1.6',
      hrProcessorTable => '1.3.6.1.2.1.25.3.3',
      hrProcessorEntry => '1.3.6.1.2.1.25.3.3.1',
      hrProcessorFrwID => '1.3.6.1.2.1.25.3.3.1.1',
      hrProcessorLoad => '1.3.6.1.2.1.25.3.3.1.2',
      hrNetworkTable => '1.3.6.1.2.1.25.3.4',
      hrNetworkEntry => '1.3.6.1.2.1.25.3.4.1',
      hrNetworkIfIndex => '1.3.6.1.2.1.25.3.4.1.1',
      hrPrinterTable => '1.3.6.1.2.1.25.3.5',
      hrPrinterEntry => '1.3.6.1.2.1.25.3.5.1',
      hrPrinterStatus => '1.3.6.1.2.1.25.3.5.1.1',
      hrPrinterDetectedErrorState => '1.3.6.1.2.1.25.3.5.1.2',
      hrDiskStorageTable => '1.3.6.1.2.1.25.3.6',
      hrDiskStorageEntry => '1.3.6.1.2.1.25.3.6.1',
      hrDiskStorageAccess => '1.3.6.1.2.1.25.3.6.1.1',
      hrDiskStorageMedia => '1.3.6.1.2.1.25.3.6.1.2',
      hrDiskStorageRemoveble => '1.3.6.1.2.1.25.3.6.1.3',
      hrDiskStorageCapacity => '1.3.6.1.2.1.25.3.6.1.4',
      hrPartitionTable => '1.3.6.1.2.1.25.3.7',
      hrPartitionEntry => '1.3.6.1.2.1.25.3.7.1',
      hrPartitionIndex => '1.3.6.1.2.1.25.3.7.1.1',
      hrPartitionLabel => '1.3.6.1.2.1.25.3.7.1.2',
      hrPartitionID => '1.3.6.1.2.1.25.3.7.1.3',
      hrPartitionSize => '1.3.6.1.2.1.25.3.7.1.4',
      hrPartitionFSIndex => '1.3.6.1.2.1.25.3.7.1.5',
      hrFSTable => '1.3.6.1.2.1.25.3.8',
      hrFSEntry => '1.3.6.1.2.1.25.3.8.1',
      hrFSIndex => '1.3.6.1.2.1.25.3.8.1.1',
      hrFSMountPoint => '1.3.6.1.2.1.25.3.8.1.2',
      hrFSRemoteMountPoint => '1.3.6.1.2.1.25.3.8.1.3',
      hrFSType => '1.3.6.1.2.1.25.3.8.1.4',
      hrFSAccess => '1.3.6.1.2.1.25.3.8.1.5',
      hrFSBootable => '1.3.6.1.2.1.25.3.8.1.6',
      hrFSStorageIndex => '1.3.6.1.2.1.25.3.8.1.7',
      hrFSLastFullBackupDate => '1.3.6.1.2.1.25.3.8.1.8',
      hrFSLastPartialBackupDate => '1.3.6.1.2.1.25.3.8.1.9',
      hrSWRun => '1.3.6.1.2.1.25.4',
      hrSWOSIndex => '1.3.6.1.2.1.25.4.1.0',
      hrSWRunTable => '1.3.6.1.2.1.25.4.2',
      hrSWRunEntry => '1.3.6.1.2.1.25.4.2.1',
      hrSWRunIndex => '1.3.6.1.2.1.25.4.2.1.1',
      hrSWRunName => '1.3.6.1.2.1.25.4.2.1.2',
      hrSWRunID => '1.3.6.1.2.1.25.4.2.1.3',
      hrSWRunPath => '1.3.6.1.2.1.25.4.2.1.4',
      hrSWRunParameters => '1.3.6.1.2.1.25.4.2.1.5',
      hrSWRunType => '1.3.6.1.2.1.25.4.2.1.6',
      hrSWRunStatus => '1.3.6.1.2.1.25.4.2.1.7',
      hrSWRunPerf => '1.3.6.1.2.1.25.5',
      hrSWRunPerfTable => '1.3.6.1.2.1.25.5.1',
      hrSWRunPerfEntry => '1.3.6.1.2.1.25.5.1.1',
      hrSWRunPerfCPU => '1.3.6.1.2.1.25.5.1.1.1',
      hrSWRunPerfMem => '1.3.6.1.2.1.25.5.1.1.2',
      hrSWInstalled => '1.3.6.1.2.1.25.6',
      hrSWInstalledLastChange => '1.3.6.1.2.1.25.6.1.0',
      hrSWInstalledLastUpdateTime => '1.3.6.1.2.1.25.6.2.0',
      hrSWInstalledTable => '1.3.6.1.2.1.25.6.3',
      hrSWInstalledEntry => '1.3.6.1.2.1.25.6.3.1',
      hrSWInstalledIndex => '1.3.6.1.2.1.25.6.3.1.1',
      hrSWInstalledName => '1.3.6.1.2.1.25.6.3.1.2',
      hrSWInstalledID => '1.3.6.1.2.1.25.6.3.1.3',
      hrSWInstalledType => '1.3.6.1.2.1.25.6.3.1.4',
      hrSWInstalledDate => '1.3.6.1.2.1.25.6.3.1.5',
  },
  'CISCO-CONFIG-MAN-MIB' => {
    ciscoConfigManMIBObjects => '1.3.6.1.4.1.9.9.43.1',
    ccmHistory => '1.3.6.1.4.1.9.9.43.1.1',
    ccmCLIHistory => '1.3.6.1.4.1.9.9.43.1.2',
    ccmCLICfg => '1.3.6.1.4.1.9.9.43.1.3',
    ccmCTIDObjects => '1.3.6.1.4.1.9.9.43.1.4',
    ccmHistory => '1.3.6.1.4.1.9.9.43.1.1',
    ccmHistoryRunningLastChanged => '1.3.6.1.4.1.9.9.43.1.1.1.0',
    ccmHistoryRunningLastSaved => '1.3.6.1.4.1.9.9.43.1.1.2.0',
    ccmHistoryStartupLastChanged => '1.3.6.1.4.1.9.9.43.1.1.3.0',
    ccmHistoryMaxEventEntries => '1.3.6.1.4.1.9.9.43.1.1.4.0',
    ccmHistoryEventEntriesBumped => '1.3.6.1.4.1.9.9.43.1.1.5.0',
  },
  'CISCO-PROCESS-MIB' => {
      cpmCPUTotalTable => '1.3.6.1.4.1.9.9.109.1.1.1',
      cpmCPUTotalEntry => '1.3.6.1.4.1.9.9.109.1.1.1.1',
      cpmCPUTotalIndex => '1.3.6.1.4.1.9.9.109.1.1.1.1.1',
      cpmCPUTotalPhysicalIndex => '1.3.6.1.4.1.9.9.109.1.1.1.1.2',
      cpmCPUTotal5sec => '1.3.6.1.4.1.9.9.109.1.1.1.1.3',
      cpmCPUTotal1min => '1.3.6.1.4.1.9.9.109.1.1.1.1.4',
      cpmCPUTotal5min => '1.3.6.1.4.1.9.9.109.1.1.1.1.5',
      cpmCPUTotal5secRev => '1.3.6.1.4.1.9.9.109.1.1.1.1.6',
      cpmCPUTotal1minRev => '1.3.6.1.4.1.9.9.109.1.1.1.1.7',
      cpmCPUTotal5minRev => '1.3.6.1.4.1.9.9.109.1.1.1.1.8',
      cpmCPUMonInterval => '1.3.6.1.4.1.9.9.109.1.1.1.1.9',
      cpmCPUTotalMonIntervalDefinition => '1.3.6.1.4.1.9.9.109.1.1.1.1.10',
      cpmCPUInterruptMonIntervalDefinition => '1.3.6.1.4.1.9.9.109.1.1.1.1.11',
      # INDEX { cpmCPUTotalIndex }
  },
  'CISCO-MEMORY-POOL-MIB' => {
      ciscoMemoryPoolTable => '1.3.6.1.4.1.9.9.48.1.1',
      ciscoMemoryPoolEntry => '1.3.6.1.4.1.9.9.48.1.1.1',
      ciscoMemoryPoolType => '1.3.6.1.4.1.9.9.48.1.1.1.1',
      ciscoMemoryPoolTypeDefinition => {
          1 => 'processor memory',
          2 => 'i/o memory',
          3 => 'pci memory',
          4 => 'fast memory',
          5 => 'multibus memory',
      },
      ciscoMemoryPoolName => '1.3.6.1.4.1.9.9.48.1.1.1.2',
      ciscoMemoryPoolAlternate => '1.3.6.1.4.1.9.9.48.1.1.1.3',
      ciscoMemoryPoolValid => '1.3.6.1.4.1.9.9.48.1.1.1.4',
      ciscoMemoryPoolUsed => '1.3.6.1.4.1.9.9.48.1.1.1.5',
      ciscoMemoryPoolFree => '1.3.6.1.4.1.9.9.48.1.1.1.6',
      ciscoMemoryPoolLargestFree => '1.3.6.1.4.1.9.9.48.1.1.1.7',
      # INDEX { ciscoMemoryPoolType }
  },
  'CISCO-ENHANCED-MEMPOOL-MIB' => {
    ciscoEnhancedMemPoolMIB => '1.3.6.1.4.1.9.9.221',
    cempMIBNotifications => '1.3.6.1.4.1.9.9.221',
    cempMIBObjects => '1.3.6.1.4.1.9.9.221.1',
    cempMIBConformance => '1.3.6.1.4.1.9.9.221.3',
    cempMemPool => '1.3.6.1.4.1.9.9.221.1.1',
    cempNotificationConfig => '1.3.6.1.4.1.9.9.221.1.2',
    cempMemPoolTable => '1.3.6.1.4.1.9.9.221.1.1.1',
    cempMemBufferPoolTable => '1.3.6.1.4.1.9.9.221.1.1.2',
    cempMemBufferCachePoolTable => '1.3.6.1.4.1.9.9.221.1.1.3',
    cempMemPoolEntry => '1.3.6.1.4.1.9.9.221.1.1.1.1',
    cempMemPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.1.1.1',
    cempMemPoolType => '1.3.6.1.4.1.9.9.221.1.1.1.1.2',
    cempMemPoolName => '1.3.6.1.4.1.9.9.221.1.1.1.1.3',
    cempMemPoolPlatformMemory => '1.3.6.1.4.1.9.9.221.1.1.1.1.4',
    cempMemPoolAlternate => '1.3.6.1.4.1.9.9.221.1.1.1.1.5',
    cempMemPoolValid => '1.3.6.1.4.1.9.9.221.1.1.1.1.6',
    cempMemPoolUsed => '1.3.6.1.4.1.9.9.221.1.1.1.1.7',
    cempMemPoolFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.8',
    cempMemPoolLargestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.9',
    cempMemPoolLowestFree => '1.3.6.1.4.1.9.9.221.1.1.1.1.10',
    cempMemPoolUsedLowWaterMark => '1.3.6.1.4.1.9.9.221.1.1.1.1.11',
    cempMemPoolAllocHit => '1.3.6.1.4.1.9.9.221.1.1.1.1.12',
    cempMemPoolAllocMiss => '1.3.6.1.4.1.9.9.221.1.1.1.1.13',
    cempMemPoolFreeHit => '1.3.6.1.4.1.9.9.221.1.1.1.1.14',
    cempMemPoolFreeMiss => '1.3.6.1.4.1.9.9.221.1.1.1.1.15',
    cempMemBufferPoolEntry => '1.3.6.1.4.1.9.9.221.1.1.2.1',
    cempMemBufferPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.2.1.1',
    cempMemBufferMemPoolIndex => '1.3.6.1.4.1.9.9.221.1.1.2.1.2',
    cempMemBufferName => '1.3.6.1.4.1.9.9.221.1.1.2.1.3',
    cempMemBufferDynamic => '1.3.6.1.4.1.9.9.221.1.1.2.1.4',
    cempMemBufferSize => '1.3.6.1.4.1.9.9.221.1.1.2.1.5',
    cempMemBufferMin => '1.3.6.1.4.1.9.9.221.1.1.2.1.6',
    cempMemBufferMax => '1.3.6.1.4.1.9.9.221.1.1.2.1.7',
    cempMemBufferPermanent => '1.3.6.1.4.1.9.9.221.1.1.2.1.8',
    cempMemBufferTransient => '1.3.6.1.4.1.9.9.221.1.1.2.1.9',
    cempMemBufferTotal => '1.3.6.1.4.1.9.9.221.1.1.2.1.10',
    cempMemBufferFree => '1.3.6.1.4.1.9.9.221.1.1.2.1.11',
    cempMemBufferHit => '1.3.6.1.4.1.9.9.221.1.1.2.1.12',
    cempMemBufferMiss => '1.3.6.1.4.1.9.9.221.1.1.2.1.13',
    cempMemBufferFreeHit => '1.3.6.1.4.1.9.9.221.1.1.2.1.14',
    cempMemBufferFreeMiss => '1.3.6.1.4.1.9.9.221.1.1.2.1.15',
    cempMemBufferPermChange => '1.3.6.1.4.1.9.9.221.1.1.2.1.16',
    cempMemBufferPeak => '1.3.6.1.4.1.9.9.221.1.1.2.1.17',
    cempMemBufferPeakTime => '1.3.6.1.4.1.9.9.221.1.1.2.1.18',
    cempMemBufferTrim => '1.3.6.1.4.1.9.9.221.1.1.2.1.19',
    cempMemBufferGrow => '1.3.6.1.4.1.9.9.221.1.1.2.1.20',
    cempMemBufferFailures => '1.3.6.1.4.1.9.9.221.1.1.2.1.21',
    cempMemBufferNoStorage => '1.3.6.1.4.1.9.9.221.1.1.2.1.22',
    cempMemBufferCachePoolEntry => '1.3.6.1.4.1.9.9.221.1.1.3.1',
    cempMemBufferCacheSize => '1.3.6.1.4.1.9.9.221.1.1.3.1.1',
    cempMemBufferCacheTotal => '1.3.6.1.4.1.9.9.221.1.1.3.1.2',
    cempMemBufferCacheUsed => '1.3.6.1.4.1.9.9.221.1.1.3.1.3',
    cempMemBufferCacheHit => '1.3.6.1.4.1.9.9.221.1.1.3.1.4',
    cempMemBufferCacheMiss => '1.3.6.1.4.1.9.9.221.1.1.3.1.5',
    cempMemBufferCacheThreshold => '1.3.6.1.4.1.9.9.221.1.1.3.1.6',
    cempMemBufferCacheThresholdCount => '1.3.6.1.4.1.9.9.221.1.1.3.1.7',
    cempMemBufferNotifyEnabled => '1.3.6.1.4.1.9.9.221.1.2.1',
    cempMIBCompliances => '1.3.6.1.4.1.9.9.221.3.1',
    cempMIBGroups => '1.3.6.1.4.1.9.9.221.3.2',
    cempMIBCompliance => '1.3.6.1.4.1.9.9.221.3.1.1',
    cempMIBComplianceRev1 => '1.3.6.1.4.1.9.9.221.3.1.2',
    cempMIBComplianceRev2 => '1.3.6.1.4.1.9.9.221.3.1.3',
    cempMemPoolGroup => '1.3.6.1.4.1.9.9.221.3.2.1',
    cempMemPoolExtGroup => '1.3.6.1.4.1.9.9.221.3.2.2',
    cempMemBufferGroup => '1.3.6.1.4.1.9.9.221.3.2.3',
    cempMemBufferExtGroup => '1.3.6.1.4.1.9.9.221.3.2.4',
    cempMemBufferNotifyEnableGroup => '1.3.6.1.4.1.9.9.221.3.2.5',
    cempMemPoolExtGroupRev1 => '1.3.6.1.4.1.9.9.221.3.2.7',
    cempMemBufferNotifyGroup => '1.3.6.1.4.1.9.9.221.3.2.6',
  },
  'CISCO-ENVMON-MIB' => {
    ciscoEnvMonPresent => '1.3.6.1.4.1.9.9.13.1.1.0',
    ciscoEnvMonPresentDefinition => {
      1 => 'oldAgs',
      2 => 'ags',
      3 => 'c7000',
      4 => 'ci',
      6 => 'cAccessMon',
      7 => 'cat6000',
      8 => 'ubr7200',
      9 => 'cat4000',
      10 => 'c10000',
      11 => 'osr7600',
      12 => 'c7600',
      13 => 'c37xx',
      14 => 'other',
    },
    ciscoEnvMonVoltageStatusTable => '1.3.6.1.4.1.9.9.13.1.2',
    ciscoEnvMonVoltageStatusEntry => '1.3.6.1.4.1.9.9.13.1.2.1',
    ciscoEnvMonVoltageStatusIndex => '1.3.6.1.4.1.9.9.13.1.2.1.1',
    ciscoEnvMonVoltageStatusDescr => '1.3.6.1.4.1.9.9.13.1.2.1.2',
    ciscoEnvMonVoltageStatusValue => '1.3.6.1.4.1.9.9.13.1.2.1.3',
    ciscoEnvMonVoltageThresholdLow => '1.3.6.1.4.1.9.9.13.1.2.1.4',
    ciscoEnvMonVoltageThresholdHigh => '1.3.6.1.4.1.9.9.13.1.2.1.5',
    ciscoEnvMonVoltageLastShutdown => '1.3.6.1.4.1.9.9.13.1.2.1.6',
    ciscoEnvMonVoltageState => '1.3.6.1.4.1.9.9.13.1.2.1.7',
    ciscoEnvMonVoltageStateDefinition => 'CISCO-ENVMON-MIB::ciscoEnvMonState',
    ciscoEnvMonTemperatureStatusTable => '1.3.6.1.4.1.9.9.13.1.3',
    ciscoEnvMonTemperatureStatusEntry => '1.3.6.1.4.1.9.9.13.1.3.1',
    ciscoEnvMonTemperatureStatusIndex => '1.3.6.1.4.1.9.9.13.1.3.1.1',
    ciscoEnvMonTemperatureStatusDescr => '1.3.6.1.4.1.9.9.13.1.3.1.2',
    ciscoEnvMonTemperatureStatusValue => '1.3.6.1.4.1.9.9.13.1.3.1.3',
    ciscoEnvMonTemperatureThreshold => '1.3.6.1.4.1.9.9.13.1.3.1.4',
    ciscoEnvMonTemperatureLastShutdown => '1.3.6.1.4.1.9.9.13.1.3.1.5',
    ciscoEnvMonTemperatureState => '1.3.6.1.4.1.9.9.13.1.3.1.6',
    ciscoEnvMonTemperatureStateDefinition => 'CISCO-ENVMON-MIB::ciscoEnvMonState',
    ciscoEnvMonFanStatusTable => '1.3.6.1.4.1.9.9.13.1.4',
    ciscoEnvMonFanStatusEntry => '1.3.6.1.4.1.9.9.13.1.4.1',
    ciscoEnvMonFanStatusIndex => '1.3.6.1.4.1.9.9.13.1.4.1.1',
    ciscoEnvMonFanStatusDescr => '1.3.6.1.4.1.9.9.13.1.4.1.2',
    ciscoEnvMonFanState => '1.3.6.1.4.1.9.9.13.1.4.1.3',
    ciscoEnvMonFanStateDefinition => 'CISCO-ENVMON-MIB::ciscoEnvMonState',
    ciscoEnvMonSupplyStatusTable => '1.3.6.1.4.1.9.9.13.1.5',
    ciscoEnvMonSupplyStatusEntry => '1.3.6.1.4.1.9.9.13.1.5.1',
    ciscoEnvMonSupplyStatusIndex => '1.3.6.1.4.1.9.9.13.1.5.1.1',
    ciscoEnvMonSupplyStatusDescr => '1.3.6.1.4.1.9.9.13.1.5.1.2',
    ciscoEnvMonSupplyState => '1.3.6.1.4.1.9.9.13.1.5.1.3',
    ciscoEnvMonSupplyStateDefinition => 'CISCO-ENVMON-MIB::ciscoEnvMonState',
    ciscoEnvMonSupplySource => '1.3.6.1.4.1.9.9.13.1.5.1.4',
    ciscoEnvMonAlarmContacts => '1.3.6.1.4.1.9.9.13.1.6.0',
  },
  'CISCO-HSRP-MIB' => {
      cHsrpGrpTable => '1.3.6.1.4.1.9.9.106.1.2.1',
      cHsrpGrpEntry => '1.3.6.1.4.1.9.9.106.1.2.1.1',
      cHsrpGrpNumber => '1.3.6.1.4.1.9.9.106.1.2.1.1.1',
      cHsrpGrpAuth => '1.3.6.1.4.1.9.9.106.1.2.1.1.2',
      cHsrpGrpPriority => '1.3.6.1.4.1.9.9.106.1.2.1.1.3',
      cHsrpGrpPreempt => '1.3.6.1.4.1.9.9.106.1.2.1.1.4',
      cHsrpGrpPreemptDelay => '1.3.6.1.4.1.9.9.106.1.2.1.1.5',
      cHsrpGrpUseConfiguredTimers => '1.3.6.1.4.1.9.9.106.1.2.1.1.6',
      cHsrpGrpConfiguredHelloTime => '1.3.6.1.4.1.9.9.106.1.2.1.1.7',
      cHsrpGrpConfiguredHoldTime => '1.3.6.1.4.1.9.9.106.1.2.1.1.8',
      cHsrpGrpLearnedHelloTime => '1.3.6.1.4.1.9.9.106.1.2.1.1.9',
      cHsrpGrpLearnedHoldTime => '1.3.6.1.4.1.9.9.106.1.2.1.1.10',
      cHsrpGrpVirtualIpAddr => '1.3.6.1.4.1.9.9.106.1.2.1.1.11',
      cHsrpGrpUseConfigVirtualIpAddr => '1.3.6.1.4.1.9.9.106.1.2.1.1.12',
      cHsrpGrpActiveRouter => '1.3.6.1.4.1.9.9.106.1.2.1.1.13',
      cHsrpGrpStandbyRouter => '1.3.6.1.4.1.9.9.106.1.2.1.1.14',
      cHsrpGrpStandbyState => '1.3.6.1.4.1.9.9.106.1.2.1.1.15',
      cHsrpGrpStandbyStateDefinition => 'CISCO-HSRP-MIB::HsrpState',
      cHsrpGrpVirtualMacAddr => '1.3.6.1.4.1.9.9.106.1.2.1.1.16',
      cHsrpGrpEntryRowStatus => '1.3.6.1.4.1.9.9.106.1.2.1.1.17',
      cHsrpGrpEntryRowStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
      # INDEX { ifIndex, cHsrpGrpNumber }
  },
  'OLD-CISCO-CPU-MIB' => {
      'avgBusy1' => '1.3.6.1.4.1.9.2.1.57.0',
      'avgBusy5' => '1.3.6.1.4.1.9.2.1.58.0',
      'busyPer' => '1.3.6.1.4.1.9.2.1.56.0',
      'idleCount' => '1.3.6.1.4.1.9.2.1.59.0',
      'idleWired' => '1.3.6.1.4.1.9.2.1.60.0',
  },
  'CISCO-SYSTEM-EXT-MIB' => {
      cseSysCPUUtilization => '1.3.6.1.4.1.9.9.305.1.1.1.0',
      cseSysMemoryUtilization => '1.3.6.1.4.1.9.9.305.1.1.2.0',
      cseSysConfLastChange => '1.3.6.1.4.1.9.9.305.1.1.3.0',
      cseSysAutoSync => '1.3.6.1.4.1.9.9.305.1.1.4.0',
      cseSysAutoSyncState => '1.3.6.1.4.1.9.9.305.1.1.5.0',
      cseWriteErase => '1.3.6.1.4.1.9.9.305.1.1.6.0',
      cseSysConsolePortStatus => '1.3.6.1.4.1.9.9.305.1.1.7.0',
      cseSysTelnetServiceActivation => '1.3.6.1.4.1.9.9.305.1.1.8.0',
      cseSysFIPSModeActivation => '1.3.6.1.4.1.9.9.305.1.1.9.0',
      cseSysUpTime => '1.3.6.1.4.1.9.9.305.1.1.10.0',
  },
  'CISCO-ENTITY-SENSOR-MIB' => {
      entSensorValueTable => '1.3.6.1.4.1.9.9.91.1.1.1',
      entSensorValueEntry => '1.3.6.1.4.1.9.9.91.1.1.1.1',
      entSensorType => '1.3.6.1.4.1.9.9.91.1.1.1.1.1',
      entSensorTypeDefinition => 'CISCO-ENTITY-SENSOR-MIB::SensorDataType',
      entSensorScale => '1.3.6.1.4.1.9.9.91.1.1.1.1.2',
      entSensorScaleDefinition => 'CISCO-ENTITY-SENSOR-MIB::SensorDataScale',
      entSensorPrecision => '1.3.6.1.4.1.9.9.91.1.1.1.1.3',
      entSensorValue => '1.3.6.1.4.1.9.9.91.1.1.1.1.4',
      entSensorStatus => '1.3.6.1.4.1.9.9.91.1.1.1.1.5',
      entSensorStatusDefinition => 'CISCO-ENTITY-SENSOR-MIB::SensorStatus',
      entSensorValueTimeStamp => '1.3.6.1.4.1.9.9.91.1.1.1.1.6',
      entSensorValueUpdateRate => '1.3.6.1.4.1.9.9.91.1.1.1.1.7',
      entSensorMeasuredEntity => '1.3.6.1.4.1.9.9.91.1.1.1.1.8',
      entSensorThresholdTable => '1.3.6.1.4.1.9.9.91.1.2.1',
      entSensorThresholdEntry => '1.3.6.1.4.1.9.9.91.1.2.1.1',
      entSensorThresholdIndex => '1.3.6.1.4.1.9.9.91.1.2.1.1.1',
      entSensorThresholdSeverity => '1.3.6.1.4.1.9.9.91.1.2.1.1.2',
      entSensorThresholdSeverityDefinition => 'CISCO-ENTITY-SENSOR-MIB::SensorThresholdSeverity',
      entSensorThresholdRelation => '1.3.6.1.4.1.9.9.91.1.2.1.1.3',
      entSensorThresholdRelationDefinition => 'CISCO-ENTITY-SENSOR-MIB::SensorThresholdRelation',
      entSensorThresholdValue => '1.3.6.1.4.1.9.9.91.1.2.1.1.4',
      entSensorThresholdEvaluation => '1.3.6.1.4.1.9.9.91.1.2.1.1.5',
      entSensorThresholdEvaluationDefinition => 'SNMPv2-TC-v1::TruthValue',
      entSensorThresholdNotificationEnable => '1.3.6.1.4.1.9.9.91.1.2.1.1.6',
      entSensorThresholdNotificationEnableDefinition => 'SNMPv2-TC-v1::TruthValue',
  },
  'CISCO-ENTITY-FRU-CONTROL-MIB' => {
    cefcMIBObjects => '1.3.6.1.4.1.9.9.117.1',
    cefcFRUMIBNotificationPrefix => '1.3.6.1.4.1.9.9.117.2',
    cefcMIBConformance => '1.3.6.1.4.1.9.9.117.3',
    cefcFRUPower => '1.3.6.1.4.1.9.9.117.1.1',
    cefcModule => '1.3.6.1.4.1.9.9.117.1.2',
    cefcMIBNotificationEnables => '1.3.6.1.4.1.9.9.117.1.3',
    cefcFRUFan => '1.3.6.1.4.1.9.9.117.1.4',
    cefcPhysical => '1.3.6.1.4.1.9.9.117.1.5',
    cefcPowerCapacity => '1.3.6.1.4.1.9.9.117.1.6',
    cefcCooling => '1.3.6.1.4.1.9.9.117.1.7',
    cefcConnector => '1.3.6.1.4.1.9.9.117.1.8',
    cefcFRUPower => '1.3.6.1.4.1.9.9.117.1.1',
    cefcFRUPowerSupplyGroupTable => '1.3.6.1.4.1.9.9.117.1.1.1',
    cefcFRUPowerSupplyGroupEntry => '1.3.6.1.4.1.9.9.117.1.1.1.1',
    cefcPowerRedundancyMode => '1.3.6.1.4.1.9.9.117.1.1.1.1.1',
    cefcPowerRedundancyModeDefinition => 'CISCO-ENTITY-FRU-CONTROL-MIB::PowerRedundancyType',
    cefcPowerUnits => '1.3.6.1.4.1.9.9.117.1.1.1.1.2',
    cefcTotalAvailableCurrent => '1.3.6.1.4.1.9.9.117.1.1.1.1.3',
    cefcTotalDrawnCurrent => '1.3.6.1.4.1.9.9.117.1.1.1.1.4',
    cefcPowerRedundancyOperMode => '1.3.6.1.4.1.9.9.117.1.1.1.1.5',
    cefcPowerRedundancyOperModeDefinition => 'CISCO-ENTITY-FRU-CONTROL-MIB::PowerRedundancyType',
    cefcPowerNonRedundantReason => '1.3.6.1.4.1.9.9.117.1.1.1.1.6',
    cefcPowerNonRedundantReasonDefinition => 'CISCO-ENTITY-FRU-CONTROL-MIB::PowerRedundancyType',
    cefcTotalDrawnInlineCurrent => '1.3.6.1.4.1.9.9.117.1.1.1.1.7',
    cefcFRUPowerStatusTable => '1.3.6.1.4.1.9.9.117.1.1.2',
    cefcFRUPowerStatusEntry => '1.3.6.1.4.1.9.9.117.1.1.2.1',
    cefcFRUPowerAdminStatus => '1.3.6.1.4.1.9.9.117.1.1.2.1.1',
    cefcFRUPowerAdminStatusDefinition => 'CISCO-ENTITY-FRU-CONTROL-MIB::PowerAdminType',
    cefcFRUPowerOperStatus => '1.3.6.1.4.1.9.9.117.1.1.2.1.2',
    cefcFRUPowerOperStatusDefinition => 'CISCO-ENTITY-FRU-CONTROL-MIB::PowerOperType',
    cefcFRUCurrent => '1.3.6.1.4.1.9.9.117.1.1.2.1.3',
    cefcFRUPowerCapability => '1.3.6.1.4.1.9.9.117.1.1.2.1.4',
    cefcFRURealTimeCurrent => '1.3.6.1.4.1.9.9.117.1.1.2.1.5',
    cefcMaxDefaultInLinePower => '1.3.6.1.4.1.9.9.117.1.1.3.0',
    cefcFRUPowerSupplyValueTable => '1.3.6.1.4.1.9.9.117.1.1.4',
    cefcFRUPowerSupplyValueEntry => '1.3.6.1.4.1.9.9.117.1.1.4.1',
    cefcFRUTotalSystemCurrent => '1.3.6.1.4.1.9.9.117.1.1.4.1.1',
    cefcFRUDrawnSystemCurrent => '1.3.6.1.4.1.9.9.117.1.1.4.1.2',
    cefcFRUTotalInlineCurrent => '1.3.6.1.4.1.9.9.117.1.1.4.1.3',
    cefcFRUDrawnInlineCurrent => '1.3.6.1.4.1.9.9.117.1.1.4.1.4',
    cefcMaxDefaultHighInLinePower => '1.3.6.1.4.1.9.9.117.1.1.5.0',
    cefcModule => '1.3.6.1.4.1.9.9.117.1.2',
    cefcModuleTable => '1.3.6.1.4.1.9.9.117.1.2.1',
    cefcModuleEntry => '1.3.6.1.4.1.9.9.117.1.2.1.1',
    cefcModuleAdminStatus => '1.3.6.1.4.1.9.9.117.1.2.1.1.1',
    cefcModuleOperStatus => '1.3.6.1.4.1.9.9.117.1.2.1.1.2',
    cefcModuleResetReason => '1.3.6.1.4.1.9.9.117.1.2.1.1.3',
    cefcModuleStatusLastChangeTime => '1.3.6.1.4.1.9.9.117.1.2.1.1.4',
    cefcModuleLastClearConfigTime => '1.3.6.1.4.1.9.9.117.1.2.1.1.5',
    cefcModuleResetReasonDescription => '1.3.6.1.4.1.9.9.117.1.2.1.1.6',
    cefcModuleStateChangeReasonDescr => '1.3.6.1.4.1.9.9.117.1.2.1.1.7',
    cefcModuleUpTime => '1.3.6.1.4.1.9.9.117.1.2.1.1.8',
    cefcIntelliModuleTable => '1.3.6.1.4.1.9.9.117.1.2.2',
    cefcIntelliModuleEntry => '1.3.6.1.4.1.9.9.117.1.2.2.1',
    cefcIntelliModuleIPAddrType => '1.3.6.1.4.1.9.9.117.1.2.2.1.1',
    cefcIntelliModuleIPAddr => '1.3.6.1.4.1.9.9.117.1.2.2.1.2',
    cefcModuleLocalSwitchingTable => '1.3.6.1.4.1.9.9.117.1.2.3',
    cefcModuleLocalSwitchingEntry => '1.3.6.1.4.1.9.9.117.1.2.3.1',
    cefcModuleLocalSwitchingMode => '1.3.6.1.4.1.9.9.117.1.2.3.1.1',
    cefcFRUFan => '1.3.6.1.4.1.9.9.117.1.4',
    cefcFanTrayStatusTable => '1.3.6.1.4.1.9.9.117.1.4.1',
    cefcFanTrayStatusEntry => '1.3.6.1.4.1.9.9.117.1.4.1.1',
    cefcFanTrayOperStatus => '1.3.6.1.4.1.9.9.117.1.4.1.1.1',
    cefcFanTrayOperStatusDefinition => {
      1 => 'unknown',
      2 => 'up',
      3 => 'down',
      4 => 'warning',
    },
    cefcPhysical => '1.3.6.1.4.1.9.9.117.1.5',
    cefcPhysicalTable => '1.3.6.1.4.1.9.9.117.1.5.1',
    cefcPhysicalEntry => '1.3.6.1.4.1.9.9.117.1.5.1.1',
    cefcPhysicalStatus => '1.3.6.1.4.1.9.9.117.1.5.1.1.1',
    cefcPowerCapacity => '1.3.6.1.4.1.9.9.117.1.6',
    cefcPowerSupplyInputTable => '1.3.6.1.4.1.9.9.117.1.6.1',
    cefcPowerSupplyInputEntry => '1.3.6.1.4.1.9.9.117.1.6.1.1',
    cefcPowerSupplyInputIndex => '1.3.6.1.4.1.9.9.117.1.6.1.1.1',
    cefcPowerSupplyInputType => '1.3.6.1.4.1.9.9.117.1.6.1.1.2',
    cefcPowerSupplyOutputTable => '1.3.6.1.4.1.9.9.117.1.6.2',
    cefcPowerSupplyOutputEntry => '1.3.6.1.4.1.9.9.117.1.6.2.1',
    cefcPSOutputModeIndex => '1.3.6.1.4.1.9.9.117.1.6.2.1.1',
    cefcPSOutputModeCurrent => '1.3.6.1.4.1.9.9.117.1.6.2.1.2',
    cefcPSOutputModeInOperation => '1.3.6.1.4.1.9.9.117.1.6.2.1.3',
    cefcCooling => '1.3.6.1.4.1.9.9.117.1.7',
    cefcChassisCoolingTable => '1.3.6.1.4.1.9.9.117.1.7.1',
    cefcChassisCoolingEntry => '1.3.6.1.4.1.9.9.117.1.7.1.1',
    cefcChassisPerSlotCoolingCap => '1.3.6.1.4.1.9.9.117.1.7.1.1.1',
    cefcChassisPerSlotCoolingUnit => '1.3.6.1.4.1.9.9.117.1.7.1.1.2',
    cefcFanCoolingTable => '1.3.6.1.4.1.9.9.117.1.7.2',
    cefcFanCoolingEntry => '1.3.6.1.4.1.9.9.117.1.7.2.1',
    cefcFanCoolingCapacity => '1.3.6.1.4.1.9.9.117.1.7.2.1.1',
    cefcFanCoolingCapacityUnit => '1.3.6.1.4.1.9.9.117.1.7.2.1.2',
    cefcModuleCoolingTable => '1.3.6.1.4.1.9.9.117.1.7.3',
    cefcModuleCoolingEntry => '1.3.6.1.4.1.9.9.117.1.7.3.1',
    cefcModuleCooling => '1.3.6.1.4.1.9.9.117.1.7.3.1.1',
    cefcModuleCoolingUnit => '1.3.6.1.4.1.9.9.117.1.7.3.1.2',
    cefcFanCoolingCapTable => '1.3.6.1.4.1.9.9.117.1.7.4',
    cefcFanCoolingCapEntry => '1.3.6.1.4.1.9.9.117.1.7.4.1',
    cefcFanCoolingCapIndex => '1.3.6.1.4.1.9.9.117.1.7.4.1.1',
    cefcFanCoolingCapModeDescr => '1.3.6.1.4.1.9.9.117.1.7.4.1.2',
    cefcFanCoolingCapCapacity => '1.3.6.1.4.1.9.9.117.1.7.4.1.3',
    cefcFanCoolingCapCurrent => '1.3.6.1.4.1.9.9.117.1.7.4.1.4',
    cefcFanCoolingCapCapacityUnit => '1.3.6.1.4.1.9.9.117.1.7.4.1.5',
    cefcConnector => '1.3.6.1.4.1.9.9.117.1.8',
    cefcConnectorRatingTable => '1.3.6.1.4.1.9.9.117.1.8.1',
    cefcConnectorRatingEntry => '1.3.6.1.4.1.9.9.117.1.8.1.1',
    cefcConnectorRating => '1.3.6.1.4.1.9.9.117.1.8.1.1.1',
    cefcModulePowerConsumptionTable => '1.3.6.1.4.1.9.9.117.1.8.2',
    cefcModulePowerConsumptionEntry => '1.3.6.1.4.1.9.9.117.1.8.2.1',
    cefcModulePowerConsumption => '1.3.6.1.4.1.9.9.117.1.8.2.1.1',
    cefcMIBNotificationEnables => '1.3.6.1.4.1.9.9.117.1.3',
    cefcMIBEnableStatusNotification => '1.3.6.1.4.1.9.9.117.1.3.1.0',
    cefcEnablePSOutputChangeNotif => '1.3.6.1.4.1.9.9.117.1.3.2.0',
  },
  'CISCO-ENTITY-ALARM-MIB' => {
    ciscoEntityAlarmMIBObjects => '1.3.6.1.4.1.9.9.138.1',
    ceAlarmDescription => '1.3.6.1.4.1.9.9.138.1.1',
    ceAlarmMonitoring => '1.3.6.1.4.1.9.9.138.1.2',
    ceAlarmHistory => '1.3.6.1.4.1.9.9.138.1.3',
    ceAlarmFiltering => '1.3.6.1.4.1.9.9.138.1.4',
    ceAlarmDescription => '1.3.6.1.4.1.9.9.138.1.1',
    ceAlarmDescrMapTable => '1.3.6.1.4.1.9.9.138.1.1.1',
    ceAlarmDescrMapEntry => '1.3.6.1.4.1.9.9.138.1.1.1.1',
    ceAlarmDescrIndex => '1.3.6.1.4.1.9.9.138.1.1.1.1.1',
    ceAlarmDescrVendorType => '1.3.6.1.4.1.9.9.138.1.1.1.1.2',
    ceAlarmDescrTable => '1.3.6.1.4.1.9.9.138.1.1.2',
    ceAlarmDescrEntry => '1.3.6.1.4.1.9.9.138.1.1.2.1',
    ceAlarmDescrAlarmType => '1.3.6.1.4.1.9.9.138.1.1.2.1.1',
    ceAlarmDescrSeverity => '1.3.6.1.4.1.9.9.138.1.1.2.1.2',
    ceAlarmDescrSeverityDefinition => 'CISCO-ENTITY-ALARM-MIB::AlarmSeverityOrZero',
    ceAlarmDescrText => '1.3.6.1.4.1.9.9.138.1.1.2.1.3',
    ceAlarmMonitoring => '1.3.6.1.4.1.9.9.138.1.2',
    ceAlarmCriticalCount => '1.3.6.1.4.1.9.9.138.1.2.1.0',
    ceAlarmMajorCount => '1.3.6.1.4.1.9.9.138.1.2.2.0',
    ceAlarmMinorCount => '1.3.6.1.4.1.9.9.138.1.2.3.0',
    ceAlarmCutOff => '1.3.6.1.4.1.9.9.138.1.2.4.0',
    ceAlarmTable => '1.3.6.1.4.1.9.9.138.1.2.5',
    ceAlarmEntry => '1.3.6.1.4.1.9.9.138.1.2.5.1',
    ceAlarmFilterProfile => '1.3.6.1.4.1.9.9.138.1.2.5.1.1',
    ceAlarmSeverity => '1.3.6.1.4.1.9.9.138.1.2.5.1.2',
    ceAlarmSeverityDefinition => 'CISCO-ENTITY-ALARM-MIB::AlarmSeverityOrZero',
    ceAlarmList => '1.3.6.1.4.1.9.9.138.1.2.5.1.3',
    ceAlarmHistory => '1.3.6.1.4.1.9.9.138.1.3',
    ceAlarmHistTableSize => '1.3.6.1.4.1.9.9.138.1.3.1.0',
    ceAlarmHistLastIndex => '1.3.6.1.4.1.9.9.138.1.3.2.0',
    ceAlarmHistTable => '1.3.6.1.4.1.9.9.138.1.3.3',
    ceAlarmHistEntry => '1.3.6.1.4.1.9.9.138.1.3.3.1',
    ceAlarmHistIndex => '1.3.6.1.4.1.9.9.138.1.3.3.1.1',
    ceAlarmHistType => '1.3.6.1.4.1.9.9.138.1.3.3.1.2',
    ceAlarmHistTypeDefinition => {
        1 => 'asserted',
        2 => 'cleared',
    },
    ceAlarmHistEntPhysicalIndex => '1.3.6.1.4.1.9.9.138.1.3.3.1.3',
    ceAlarmHistAlarmType => '1.3.6.1.4.1.9.9.138.1.3.3.1.4',
    ceAlarmHistSeverity => '1.3.6.1.4.1.9.9.138.1.3.3.1.5',
    ceAlarmHistSeverityDefinition => 'CISCO-ENTITY-ALARM-MIB::AlarmSeverityOrZero',
    ceAlarmHistTimeStamp => '1.3.6.1.4.1.9.9.138.1.3.3.1.6',
    ceAlarmFiltering => '1.3.6.1.4.1.9.9.138.1.4',
    ceAlarmNotifiesEnable => '1.3.6.1.4.1.9.9.138.1.4.1.0',
    ceAlarmSyslogEnable => '1.3.6.1.4.1.9.9.138.1.4.2.0',
    ceAlarmFilterProfileIndexNext => '1.3.6.1.4.1.9.9.138.1.4.3.0',
    ceAlarmFilterProfileTable => '1.3.6.1.4.1.9.9.138.1.4.4',
    ceAlarmFilterProfileEntry => '1.3.6.1.4.1.9.9.138.1.4.4.1',
    ceAlarmFilterIndex => '1.3.6.1.4.1.9.9.138.1.4.4.1.1',
    ceAlarmFilterStatus => '1.3.6.1.4.1.9.9.138.1.4.4.1.2',
    ceAlarmFilterAlias => '1.3.6.1.4.1.9.9.138.1.4.4.1.3',
    ceAlarmFilterAlarmsEnabled => '1.3.6.1.4.1.9.9.138.1.4.4.1.4',
    ceAlarmFilterNotifiesEnabled => '1.3.6.1.4.1.9.9.138.1.4.4.1.5',
    ceAlarmFilterSyslogEnabled => '1.3.6.1.4.1.9.9.138.1.4.4.1.6',
    ciscoEntityAlarmMIBNotificationsPrefix => '1.3.6.1.4.1.9.9.138.2',
    ciscoEntityAlarmMIBNotifications => '1.3.6.1.4.1.9.9.138.2.0',
    ceAlarmAsserted => '1.3.6.1.4.1.9.9.138.2.0.1',
    ceAlarmCleared => '1.3.6.1.4.1.9.9.138.2.0.2',
    ciscoEntityAlarmMIBConformance => '1.3.6.1.4.1.9.9.138.3',
    ciscoEntityAlarmMIBCompliances => '1.3.6.1.4.1.9.9.138.3.1',
    ciscoEntityAlarmMIBGroups => '1.3.6.1.4.1.9.9.138.3.2',
  },
  'CISCO-L2L3-INTERFACE-CONFIG-MIB' => {
      cL2L3IfTable => '1.3.6.1.4.1.9.9.151.1.1.1',
      cL2L3IfEntry => '1.3.6.1.4.1.9.9.151.1.1.1.1',
      cL2L3IfModeAdmin => '1.3.6.1.4.1.9.9.151.1.1.1.1.1',
      cL2L3IfModeAdminDefinition => 'CISCO-L2L3-INTERFACE-CONFIG-MIB::CL2L3InterfaceMode',
      cL2L3IfModeOper => '1.3.6.1.4.1.9.9.151.1.1.1.1.2',
      cL2L3IfModeOperDefinition => 'CISCO-L2L3-INTERFACE-CONFIG-MIB::CL2L3InterfaceMode',
  },
  'CISCO-VTP-MIB' => {
      vlanTrunkPortTable => '1.3.6.1.4.1.9.9.46.1.6.1',
      vlanTrunkPortEntry => '1.3.6.1.4.1.9.9.46.1.6.1.1',
      vlanTrunkPortIfIndex => '1.3.6.1.4.1.9.9.46.1.6.1.1.1',
      vlanTrunkPortVlansPruningEligible => '1.3.6.1.4.1.9.9.46.1.6.1.1.10',
      vlanTrunkPortVlansXmitJoined => '1.3.6.1.4.1.9.9.46.1.6.1.1.11',
      vlanTrunkPortVlansRcvJoined => '1.3.6.1.4.1.9.9.46.1.6.1.1.12',
      vlanTrunkPortDynamicState => '1.3.6.1.4.1.9.9.46.1.6.1.1.13',
      vlanTrunkPortDynamicStatus => '1.3.6.1.4.1.9.9.46.1.6.1.1.14',
      vlanTrunkPortDynamicStatusDefinition => {
          1 => 'trunking',
          2 => 'notTrunking',
      },
      vlanTrunkPortVtpEnabled => '1.3.6.1.4.1.9.9.46.1.6.1.1.15',
      vlanTrunkPortEncapsulationOperType => '1.3.6.1.4.1.9.9.46.1.6.1.1.16',
      vlanTrunkPortVlansEnabled2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.17',
      vlanTrunkPortVlansEnabled3k => '1.3.6.1.4.1.9.9.46.1.6.1.1.18',
      vlanTrunkPortVlansEnabled4k => '1.3.6.1.4.1.9.9.46.1.6.1.1.19',
      vlanTrunkPortManagementDomain => '1.3.6.1.4.1.9.9.46.1.6.1.1.2',
      vtpVlansPruningEligible2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.20',
      vtpVlansPruningEligible3k => '1.3.6.1.4.1.9.9.46.1.6.1.1.21',
      vtpVlansPruningEligible4k => '1.3.6.1.4.1.9.9.46.1.6.1.1.22',
      vlanTrunkPortVlansXmitJoined2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.23',
      vlanTrunkPortVlansXmitJoined3k => '1.3.6.1.4.1.9.9.46.1.6.1.1.24',
      vlanTrunkPortVlansXmitJoined4k => '1.3.6.1.4.1.9.9.46.1.6.1.1.25',
      vlanTrunkPortVlansRcvJoined2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.26',
      vlanTrunkPortVlansRcvJoined3k => '1.3.6.1.4.1.9.9.46.1.6.1.1.27',
      vlanTrunkPortVlansRcvJoined4k => '1.3.6.1.4.1.9.9.46.1.6.1.1.28',
      vlanTrunkPortDot1qTunnel => '1.3.6.1.4.1.9.9.46.1.6.1.1.29',
      vlanTrunkPortEncapsulationType => '1.3.6.1.4.1.9.9.46.1.6.1.1.3',
      vlanTrunkPortVlansActiveFirst2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.30',
      vlanTrunkPortVlansActiveSecond2k => '1.3.6.1.4.1.9.9.46.1.6.1.1.31',
      vlanTrunkPortVlansEnabled => '1.3.6.1.4.1.9.9.46.1.6.1.1.4',
      vlanTrunkPortNativeVlan => '1.3.6.1.4.1.9.9.46.1.6.1.1.5',
      vlanTrunkPortRowStatus => '1.3.6.1.4.1.9.9.46.1.6.1.1.6',
      vlanTrunkPortInJoins => '1.3.6.1.4.1.9.9.46.1.6.1.1.7',
      vlanTrunkPortOutJoins => '1.3.6.1.4.1.9.9.46.1.6.1.1.8',
      vlanTrunkPortOldAdverts => '1.3.6.1.4.1.9.9.46.1.6.1.1.9',
  },
  'CISCO-FIREWALL-MIB' => {
      cfwConnectionStatTable => '1.3.6.1.4.1.9.9.147.1.2.2.2',
      cfwConnectionStatEntry => '1.3.6.1.4.1.9.9.147.1.2.2.2.1',
      cfwConnectionStatService => '1.3.6.1.4.1.9.9.147.1.2.2.2.1.1',
      cfwConnectionStatServiceDefinition => 'CISCO-FIREWALL-MIB::Services',
      cfwConnectionStatType => '1.3.6.1.4.1.9.9.147.1.2.2.2.1.2',
      cfwConnectionStatDescription => '1.3.6.1.4.1.9.9.147.1.2.2.2.1.3',
      cfwConnectionStatCount => '1.3.6.1.4.1.9.9.147.1.2.2.2.1.4', #Counter
      cfwConnectionStatValue => '1.3.6.1.4.1.9.9.147.1.2.2.2.1.5', #Gauge
  },
  'CISCO-CCM-MIB' => {
    org => '1.3',
    dod => '1.3.6',
    internet => '1.3.6.1',
    directory => '1.3.6.1.1',
    mgmt => '1.3.6.1.2',
    experimental => '1.3.6.1.3',
    private => '1.3.6.1.4',
    enterprises => '1.3.6.1.4.1',
    cisco => '1.3.6.1.4.1.9',
    ciscoMgmt => '1.3.6.1.4.1.9.9',
    ciscoCcmMIB => '1.3.6.1.4.1.9.9.156',
    ciscoCcmMIBObjects => '1.3.6.1.4.1.9.9.156.1',
    ccmMIBNotificationPrefix => '1.3.6.1.4.1.9.9.156.2',
    ciscoCcmMIBConformance => '1.3.6.1.4.1.9.9.156.3',
    ccmGeneralInfo => '1.3.6.1.4.1.9.9.156.1.1',
    ccmPhoneInfo => '1.3.6.1.4.1.9.9.156.1.2',
    ccmGatewayInfo => '1.3.6.1.4.1.9.9.156.1.3',
    ccmGatewayTrunkInfo => '1.3.6.1.4.1.9.9.156.1.4',
    ccmGlobalInfo => '1.3.6.1.4.1.9.9.156.1.5',
    ccmMediaDeviceInfo => '1.3.6.1.4.1.9.9.156.1.6',
    ccmGatekeeperInfo => '1.3.6.1.4.1.9.9.156.1.7',
    ccmCTIDeviceInfo => '1.3.6.1.4.1.9.9.156.1.8',
    ccmAlarmConfigInfo => '1.3.6.1.4.1.9.9.156.1.9',
    ccmNotificationsInfo => '1.3.6.1.4.1.9.9.156.1.10',
    ccmH323DeviceInfo => '1.3.6.1.4.1.9.9.156.1.11',
    ccmVoiceMailDeviceInfo => '1.3.6.1.4.1.9.9.156.1.12',
    ccmQualityReportAlarmConfigInfo => '1.3.6.1.4.1.9.9.156.1.13',
    ccmSIPDeviceInfo => '1.3.6.1.4.1.9.9.156.1.14',
    ccmGroupTable => '1.3.6.1.4.1.9.9.156.1.1.1',
    ccmTable => '1.3.6.1.4.1.9.9.156.1.1.2',
    ccmGroupMappingTable => '1.3.6.1.4.1.9.9.156.1.1.3',
    ccmRegionTable => '1.3.6.1.4.1.9.9.156.1.1.4',
    ccmRegionPairTable => '1.3.6.1.4.1.9.9.156.1.1.5',
    ccmTimeZoneTable => '1.3.6.1.4.1.9.9.156.1.1.6',
    ccmDevicePoolTable => '1.3.6.1.4.1.9.9.156.1.1.7',
    ccmProductTypeTable => '1.3.6.1.4.1.9.9.156.1.1.8',
    ccmGroupEntry => '1.3.6.1.4.1.9.9.156.1.1.1.1',
    ccmGroupIndex => '1.3.6.1.4.1.9.9.156.1.1.1.1.1',
    ccmGroupName => '1.3.6.1.4.1.9.9.156.1.1.1.1.2',
    ccmGroupTftpDefault => '1.3.6.1.4.1.9.9.156.1.1.1.1.3',
    ccmEntry => '1.3.6.1.4.1.9.9.156.1.1.2.1',
    ccmIndex => '1.3.6.1.4.1.9.9.156.1.1.2.1.1',
    ccmName => '1.3.6.1.4.1.9.9.156.1.1.2.1.2',
    ccmDescription => '1.3.6.1.4.1.9.9.156.1.1.2.1.3',
    ccmVersion => '1.3.6.1.4.1.9.9.156.1.1.2.1.4',
    ccmStatus => '1.3.6.1.4.1.9.9.156.1.1.2.1.5',
    ccmStatusDefinition => {
      1 => 'unknown',
      2 => 'up',
      3 => 'down',
    },
    ccmInetAddressType => '1.3.6.1.4.1.9.9.156.1.1.2.1.6',
    ccmInetAddress => '1.3.6.1.4.1.9.9.156.1.1.2.1.7',
    ccmClusterId => '1.3.6.1.4.1.9.9.156.1.1.2.1.8',
    ccmInetAddress2Type => '1.3.6.1.4.1.9.9.156.1.1.2.1.9',
    ccmInetAddress2 => '1.3.6.1.4.1.9.9.156.1.1.2.1.10',
    ccmGroupMappingEntry => '1.3.6.1.4.1.9.9.156.1.1.3.1',
    ccmCMGroupMappingCMPriority => '1.3.6.1.4.1.9.9.156.1.1.3.1.1',
    ccmRegionEntry => '1.3.6.1.4.1.9.9.156.1.1.4.1',
    ccmRegionIndex => '1.3.6.1.4.1.9.9.156.1.1.4.1.1',
    ccmRegionName => '1.3.6.1.4.1.9.9.156.1.1.4.1.2',
    ccmRegionPairEntry => '1.3.6.1.4.1.9.9.156.1.1.5.1',
    ccmRegionSrcIndex => '1.3.6.1.4.1.9.9.156.1.1.5.1.1',
    ccmRegionDestIndex => '1.3.6.1.4.1.9.9.156.1.1.5.1.2',
    ccmRegionAvailableBandWidth => '1.3.6.1.4.1.9.9.156.1.1.5.1.3',
    ccmTimeZoneEntry => '1.3.6.1.4.1.9.9.156.1.1.6.1',
    ccmTimeZoneIndex => '1.3.6.1.4.1.9.9.156.1.1.6.1.1',
    ccmTimeZoneName => '1.3.6.1.4.1.9.9.156.1.1.6.1.2',
    ccmTimeZoneOffset => '1.3.6.1.4.1.9.9.156.1.1.6.1.3',
    ccmTimeZoneOffsetHours => '1.3.6.1.4.1.9.9.156.1.1.6.1.4',
    ccmTimeZoneOffsetMinutes => '1.3.6.1.4.1.9.9.156.1.1.6.1.5',
    ccmDevicePoolEntry => '1.3.6.1.4.1.9.9.156.1.1.7.1',
    ccmDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.1.7.1.1',
    ccmDevicePoolName => '1.3.6.1.4.1.9.9.156.1.1.7.1.2',
    ccmDevicePoolRegionIndex => '1.3.6.1.4.1.9.9.156.1.1.7.1.3',
    ccmDevicePoolTimeZoneIndex => '1.3.6.1.4.1.9.9.156.1.1.7.1.4',
    ccmDevicePoolGroupIndex => '1.3.6.1.4.1.9.9.156.1.1.7.1.5',
    ccmProductTypeEntry => '1.3.6.1.4.1.9.9.156.1.1.8.1',
    ccmProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.1.8.1.1',
    ccmProductType => '1.3.6.1.4.1.9.9.156.1.1.8.1.2',
    ccmProductName => '1.3.6.1.4.1.9.9.156.1.1.8.1.3',
    ccmProductCategory => '1.3.6.1.4.1.9.9.156.1.1.8.1.4',
    ccmPhoneTable => '1.3.6.1.4.1.9.9.156.1.2.1',
    ccmPhoneExtensionTable => '1.3.6.1.4.1.9.9.156.1.2.2',
    ccmPhoneFailedTable => '1.3.6.1.4.1.9.9.156.1.2.3',
    ccmPhoneStatusUpdateTable => '1.3.6.1.4.1.9.9.156.1.2.4',
    ccmPhoneExtnTable => '1.3.6.1.4.1.9.9.156.1.2.5',
    ccmPhoneEntry => '1.3.6.1.4.1.9.9.156.1.2.1.1',
    ccmPhoneIndex => '1.3.6.1.4.1.9.9.156.1.2.1.1.1',
    ccmPhonePhysicalAddress => '1.3.6.1.4.1.9.9.156.1.2.1.1.2',
    ccmPhoneType => '1.3.6.1.4.1.9.9.156.1.2.1.1.3',
    ccmPhoneDescription => '1.3.6.1.4.1.9.9.156.1.2.1.1.4',
    ccmPhoneUserName => '1.3.6.1.4.1.9.9.156.1.2.1.1.5',
    ccmPhoneIpAddress => '1.3.6.1.4.1.9.9.156.1.2.1.1.6',
    ccmPhoneStatus => '1.3.6.1.4.1.9.9.156.1.2.1.1.7',
    ccmPhoneTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.2.1.1.8',
    ccmPhoneE911Location => '1.3.6.1.4.1.9.9.156.1.2.1.1.9',
    ccmPhoneLoadID => '1.3.6.1.4.1.9.9.156.1.2.1.1.10',
    ccmPhoneLastError => '1.3.6.1.4.1.9.9.156.1.2.1.1.11',
    ccmPhoneTimeLastError => '1.3.6.1.4.1.9.9.156.1.2.1.1.12',
    ccmPhoneDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.2.1.1.13',
    ccmPhoneInetAddressType => '1.3.6.1.4.1.9.9.156.1.2.1.1.14',
    ccmPhoneInetAddress => '1.3.6.1.4.1.9.9.156.1.2.1.1.15',
    ccmPhoneStatusReason => '1.3.6.1.4.1.9.9.156.1.2.1.1.16',
    ccmPhoneTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.2.1.1.17',
    ccmPhoneProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.2.1.1.18',
    ccmPhoneProtocol => '1.3.6.1.4.1.9.9.156.1.2.1.1.19',
    ccmPhoneName => '1.3.6.1.4.1.9.9.156.1.2.1.1.20',
    ccmPhoneInetAddressIPv4 => '1.3.6.1.4.1.9.9.156.1.2.1.1.21',
    ccmPhoneInetAddressIPv6 => '1.3.6.1.4.1.9.9.156.1.2.1.1.22',
    ccmPhoneIPv4Attribute => '1.3.6.1.4.1.9.9.156.1.2.1.1.23',
    ccmPhoneIPv6Attribute => '1.3.6.1.4.1.9.9.156.1.2.1.1.24',
    ccmPhoneActiveLoadID => '1.3.6.1.4.1.9.9.156.1.2.1.1.25',
    ccmPhoneUnregReason => '1.3.6.1.4.1.9.9.156.1.2.1.1.26',
    ccmPhoneRegFailReason => '1.3.6.1.4.1.9.9.156.1.2.1.1.27',
    ccmPhoneExtensionEntry => '1.3.6.1.4.1.9.9.156.1.2.2.1',
    ccmPhoneExtensionIndex => '1.3.6.1.4.1.9.9.156.1.2.2.1.1',
    ccmPhoneExtension => '1.3.6.1.4.1.9.9.156.1.2.2.1.2',
    ccmPhoneExtensionIpAddress => '1.3.6.1.4.1.9.9.156.1.2.2.1.3',
    ccmPhoneExtensionMultiLines => '1.3.6.1.4.1.9.9.156.1.2.2.1.4',
    ccmPhoneExtensionInetAddressType => '1.3.6.1.4.1.9.9.156.1.2.2.1.5',
    ccmPhoneExtensionInetAddress => '1.3.6.1.4.1.9.9.156.1.2.2.1.6',
    ccmPhoneFailedEntry => '1.3.6.1.4.1.9.9.156.1.2.3.1',
    ccmPhoneFailedIndex => '1.3.6.1.4.1.9.9.156.1.2.3.1.1',
    ccmPhoneFailedTime => '1.3.6.1.4.1.9.9.156.1.2.3.1.2',
    ccmPhoneFailedName => '1.3.6.1.4.1.9.9.156.1.2.3.1.3',
    ccmPhoneFailedInetAddressType => '1.3.6.1.4.1.9.9.156.1.2.3.1.4',
    ccmPhoneFailedInetAddress => '1.3.6.1.4.1.9.9.156.1.2.3.1.5',
    ccmPhoneFailCauseCode => '1.3.6.1.4.1.9.9.156.1.2.3.1.6',
    ccmPhoneFailedMacAddress => '1.3.6.1.4.1.9.9.156.1.2.3.1.7',
    ccmPhoneFailedInetAddressIPv4 => '1.3.6.1.4.1.9.9.156.1.2.3.1.8',
    ccmPhoneFailedInetAddressIPv6 => '1.3.6.1.4.1.9.9.156.1.2.3.1.9',
    ccmPhoneFailedIPv4Attribute => '1.3.6.1.4.1.9.9.156.1.2.3.1.10',
    ccmPhoneFailedIPv6Attribute => '1.3.6.1.4.1.9.9.156.1.2.3.1.11',
    ccmPhoneFailedRegFailReason => '1.3.6.1.4.1.9.9.156.1.2.3.1.12',
    ccmPhoneStatusUpdateEntry => '1.3.6.1.4.1.9.9.156.1.2.4.1',
    ccmPhoneStatusUpdateIndex => '1.3.6.1.4.1.9.9.156.1.2.4.1.1',
    ccmPhoneStatusPhoneIndex => '1.3.6.1.4.1.9.9.156.1.2.4.1.2',
    ccmPhoneStatusUpdateTime => '1.3.6.1.4.1.9.9.156.1.2.4.1.3',
    ccmPhoneStatusUpdateType => '1.3.6.1.4.1.9.9.156.1.2.4.1.4',
    ccmPhoneStatusUpdateReason => '1.3.6.1.4.1.9.9.156.1.2.4.1.5',
    ccmPhoneStatusUnregReason => '1.3.6.1.4.1.9.9.156.1.2.4.1.6',
    ccmPhoneStatusRegFailReason => '1.3.6.1.4.1.9.9.156.1.2.4.1.7',
    ccmPhoneExtnEntry => '1.3.6.1.4.1.9.9.156.1.2.5.1',
    ccmPhoneExtnIndex => '1.3.6.1.4.1.9.9.156.1.2.5.1.1',
    ccmPhoneExtn => '1.3.6.1.4.1.9.9.156.1.2.5.1.2',
    ccmPhoneExtnMultiLines => '1.3.6.1.4.1.9.9.156.1.2.5.1.3',
    ccmPhoneExtnInetAddressType => '1.3.6.1.4.1.9.9.156.1.2.5.1.4',
    ccmPhoneExtnInetAddress => '1.3.6.1.4.1.9.9.156.1.2.5.1.5',
    ccmPhoneExtnStatus => '1.3.6.1.4.1.9.9.156.1.2.5.1.6',
    ccmGatewayTable => '1.3.6.1.4.1.9.9.156.1.3.1',
    ccmGatewayEntry => '1.3.6.1.4.1.9.9.156.1.3.1.1',
    ccmGatewayIndex => '1.3.6.1.4.1.9.9.156.1.3.1.1.1',
    ccmGatewayName => '1.3.6.1.4.1.9.9.156.1.3.1.1.2',
    ccmGatewayType => '1.3.6.1.4.1.9.9.156.1.3.1.1.3',
    ccmGatewayDescription => '1.3.6.1.4.1.9.9.156.1.3.1.1.4',
    ccmGatewayStatus => '1.3.6.1.4.1.9.9.156.1.3.1.1.5',
    ccmGatewayDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.3.1.1.6',
    ccmGatewayInetAddressType => '1.3.6.1.4.1.9.9.156.1.3.1.1.7',
    ccmGatewayInetAddress => '1.3.6.1.4.1.9.9.156.1.3.1.1.8',
    ccmGatewayProductId => '1.3.6.1.4.1.9.9.156.1.3.1.1.9',
    ccmGatewayStatusReason => '1.3.6.1.4.1.9.9.156.1.3.1.1.10',
    ccmGatewayTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.3.1.1.11',
    ccmGatewayTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.3.1.1.12',
    ccmGatewayDChannelStatus => '1.3.6.1.4.1.9.9.156.1.3.1.1.13',
    ccmGatewayDChannelNumber => '1.3.6.1.4.1.9.9.156.1.3.1.1.14',
    ccmGatewayProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.3.1.1.15',
    ccmGatewayUnregReason => '1.3.6.1.4.1.9.9.156.1.3.1.1.16',
    ccmGatewayRegFailReason => '1.3.6.1.4.1.9.9.156.1.3.1.1.17',
    ccmGatewayTrunkTable => '1.3.6.1.4.1.9.9.156.1.4.1',
    ccmGatewayTrunkEntry => '1.3.6.1.4.1.9.9.156.1.4.1.1',
    ccmGatewayTrunkIndex => '1.3.6.1.4.1.9.9.156.1.4.1.1.1',
    ccmGatewayTrunkType => '1.3.6.1.4.1.9.9.156.1.4.1.1.2',
    ccmGatewayTrunkName => '1.3.6.1.4.1.9.9.156.1.4.1.1.3',
    ccmTrunkGatewayIndex => '1.3.6.1.4.1.9.9.156.1.4.1.1.4',
    ccmGatewayTrunkStatus => '1.3.6.1.4.1.9.9.156.1.4.1.1.5',
    ccmActivePhones => '1.3.6.1.4.1.9.9.156.1.5.1',
    ccmInActivePhones => '1.3.6.1.4.1.9.9.156.1.5.2',
    ccmActiveGateways => '1.3.6.1.4.1.9.9.156.1.5.3',
    ccmInActiveGateways => '1.3.6.1.4.1.9.9.156.1.5.4',
    ccmRegisteredPhones => '1.3.6.1.4.1.9.9.156.1.5.5',
    ccmUnregisteredPhones => '1.3.6.1.4.1.9.9.156.1.5.6',
    ccmRejectedPhones => '1.3.6.1.4.1.9.9.156.1.5.7',
    ccmRegisteredGateways => '1.3.6.1.4.1.9.9.156.1.5.8',
    ccmUnregisteredGateways => '1.3.6.1.4.1.9.9.156.1.5.9',
    ccmRejectedGateways => '1.3.6.1.4.1.9.9.156.1.5.10',
    ccmRegisteredMediaDevices => '1.3.6.1.4.1.9.9.156.1.5.11',
    ccmUnregisteredMediaDevices => '1.3.6.1.4.1.9.9.156.1.5.12',
    ccmRejectedMediaDevices => '1.3.6.1.4.1.9.9.156.1.5.13',
    ccmRegisteredCTIDevices => '1.3.6.1.4.1.9.9.156.1.5.14',
    ccmUnregisteredCTIDevices => '1.3.6.1.4.1.9.9.156.1.5.15',
    ccmRejectedCTIDevices => '1.3.6.1.4.1.9.9.156.1.5.16',
    ccmRegisteredVoiceMailDevices => '1.3.6.1.4.1.9.9.156.1.5.17',
    ccmUnregisteredVoiceMailDevices => '1.3.6.1.4.1.9.9.156.1.5.18',
    ccmRejectedVoiceMailDevices => '1.3.6.1.4.1.9.9.156.1.5.19',
    ccmCallManagerStartTime => '1.3.6.1.4.1.9.9.156.1.5.20',
    ccmPhoneTableStateId => '1.3.6.1.4.1.9.9.156.1.5.21',
    ccmPhoneExtensionTableStateId => '1.3.6.1.4.1.9.9.156.1.5.22',
    ccmPhoneStatusUpdateTableStateId => '1.3.6.1.4.1.9.9.156.1.5.23',
    ccmGatewayTableStateId => '1.3.6.1.4.1.9.9.156.1.5.24',
    ccmCTIDeviceTableStateId => '1.3.6.1.4.1.9.9.156.1.5.25',
    ccmCTIDeviceDirNumTableStateId => '1.3.6.1.4.1.9.9.156.1.5.26',
    ccmPhStatUpdtTblLastAddedIndex => '1.3.6.1.4.1.9.9.156.1.5.27',
    ccmPhFailedTblLastAddedIndex => '1.3.6.1.4.1.9.9.156.1.5.28',
    ccmSystemVersion => '1.3.6.1.4.1.9.9.156.1.5.29',
    ccmInstallationId => '1.3.6.1.4.1.9.9.156.1.5.30',
    ccmPartiallyRegisteredPhones => '1.3.6.1.4.1.9.9.156.1.5.31',
    ccmH323TableEntries => '1.3.6.1.4.1.9.9.156.1.5.32',
    ccmSIPTableEntries => '1.3.6.1.4.1.9.9.156.1.5.33',
    ccmMediaDeviceTable => '1.3.6.1.4.1.9.9.156.1.6.1',
    ccmMediaDeviceEntry => '1.3.6.1.4.1.9.9.156.1.6.1.1',
    ccmMediaDeviceIndex => '1.3.6.1.4.1.9.9.156.1.6.1.1.1',
    ccmMediaDeviceName => '1.3.6.1.4.1.9.9.156.1.6.1.1.2',
    ccmMediaDeviceType => '1.3.6.1.4.1.9.9.156.1.6.1.1.3',
    ccmMediaDeviceDescription => '1.3.6.1.4.1.9.9.156.1.6.1.1.4',
    ccmMediaDeviceStatus => '1.3.6.1.4.1.9.9.156.1.6.1.1.5',
    ccmMediaDeviceDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.6.1.1.6',
    ccmMediaDeviceInetAddressType => '1.3.6.1.4.1.9.9.156.1.6.1.1.7',
    ccmMediaDeviceInetAddress => '1.3.6.1.4.1.9.9.156.1.6.1.1.8',
    ccmMediaDeviceStatusReason => '1.3.6.1.4.1.9.9.156.1.6.1.1.9',
    ccmMediaDeviceTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.6.1.1.10',
    ccmMediaDeviceTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.6.1.1.11',
    ccmMediaDeviceProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.6.1.1.12',
    ccmMediaDeviceInetAddressIPv4 => '1.3.6.1.4.1.9.9.156.1.6.1.1.13',
    ccmMediaDeviceInetAddressIPv6 => '1.3.6.1.4.1.9.9.156.1.6.1.1.14',
    ccmMediaDeviceUnregReason => '1.3.6.1.4.1.9.9.156.1.6.1.1.15',
    ccmMediaDeviceRegFailReason => '1.3.6.1.4.1.9.9.156.1.6.1.1.16',
    ccmGatekeeperTable => '1.3.6.1.4.1.9.9.156.1.7.1',
    ccmGatekeeperEntry => '1.3.6.1.4.1.9.9.156.1.7.1.1',
    ccmGatekeeperIndex => '1.3.6.1.4.1.9.9.156.1.7.1.1.1',
    ccmGatekeeperName => '1.3.6.1.4.1.9.9.156.1.7.1.1.2',
    ccmGatekeeperType => '1.3.6.1.4.1.9.9.156.1.7.1.1.3',
    ccmGatekeeperDescription => '1.3.6.1.4.1.9.9.156.1.7.1.1.4',
    ccmGatekeeperStatus => '1.3.6.1.4.1.9.9.156.1.7.1.1.5',
    ccmGatekeeperDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.7.1.1.6',
    ccmGatekeeperInetAddressType => '1.3.6.1.4.1.9.9.156.1.7.1.1.7',
    ccmGatekeeperInetAddress => '1.3.6.1.4.1.9.9.156.1.7.1.1.8',
    ccmCTIDeviceTable => '1.3.6.1.4.1.9.9.156.1.8.1',
    ccmCTIDeviceDirNumTable => '1.3.6.1.4.1.9.9.156.1.8.2',
    ccmCTIDeviceEntry => '1.3.6.1.4.1.9.9.156.1.8.1.1',
    ccmCTIDeviceIndex => '1.3.6.1.4.1.9.9.156.1.8.1.1.1',
    ccmCTIDeviceName => '1.3.6.1.4.1.9.9.156.1.8.1.1.2',
    ccmCTIDeviceType => '1.3.6.1.4.1.9.9.156.1.8.1.1.3',
    ccmCTIDeviceDescription => '1.3.6.1.4.1.9.9.156.1.8.1.1.4',
    ccmCTIDeviceStatus => '1.3.6.1.4.1.9.9.156.1.8.1.1.5',
    ccmCTIDevicePoolIndex => '1.3.6.1.4.1.9.9.156.1.8.1.1.6',
    ccmCTIDeviceInetAddressType => '1.3.6.1.4.1.9.9.156.1.8.1.1.7',
    ccmCTIDeviceInetAddress => '1.3.6.1.4.1.9.9.156.1.8.1.1.8',
    ccmCTIDeviceAppInfo => '1.3.6.1.4.1.9.9.156.1.8.1.1.9',
    ccmCTIDeviceStatusReason => '1.3.6.1.4.1.9.9.156.1.8.1.1.10',
    ccmCTIDeviceTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.8.1.1.11',
    ccmCTIDeviceTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.8.1.1.12',
    ccmCTIDeviceProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.8.1.1.13',
    ccmCTIDeviceInetAddressIPv4 => '1.3.6.1.4.1.9.9.156.1.8.1.1.14',
    ccmCTIDeviceInetAddressIPv6 => '1.3.6.1.4.1.9.9.156.1.8.1.1.15',
    ccmCTIDeviceUnregReason => '1.3.6.1.4.1.9.9.156.1.8.1.1.16',
    ccmCTIDeviceRegFailReason => '1.3.6.1.4.1.9.9.156.1.8.1.1.17',
    ccmCTIDeviceDirNumEntry => '1.3.6.1.4.1.9.9.156.1.8.2.1',
    ccmCTIDeviceDirNumIndex => '1.3.6.1.4.1.9.9.156.1.8.2.1.1',
    ccmCTIDeviceDirNum => '1.3.6.1.4.1.9.9.156.1.8.2.1.2',
    ccmCallManagerAlarmEnable => '1.3.6.1.4.1.9.9.156.1.9.1',
    ccmPhoneFailedAlarmInterval => '1.3.6.1.4.1.9.9.156.1.9.2',
    ccmPhoneFailedStorePeriod => '1.3.6.1.4.1.9.9.156.1.9.3',
    ccmPhoneStatusUpdateAlarmInterv => '1.3.6.1.4.1.9.9.156.1.9.4',
    ccmPhoneStatusUpdateStorePeriod => '1.3.6.1.4.1.9.9.156.1.9.5',
    ccmGatewayAlarmEnable => '1.3.6.1.4.1.9.9.156.1.9.6',
    ccmMaliciousCallAlarmEnable => '1.3.6.1.4.1.9.9.156.1.9.7',
    ccmAlarmSeverity => '1.3.6.1.4.1.9.9.156.1.10.1',
    ccmFailCauseCode => '1.3.6.1.4.1.9.9.156.1.10.2',
    ccmPhoneFailures => '1.3.6.1.4.1.9.9.156.1.10.3',
    ccmPhoneUpdates => '1.3.6.1.4.1.9.9.156.1.10.4',
    ccmGatewayFailCauseCode => '1.3.6.1.4.1.9.9.156.1.10.5',
    ccmMediaResourceType => '1.3.6.1.4.1.9.9.156.1.10.6',
    ccmMediaResourceListName => '1.3.6.1.4.1.9.9.156.1.10.7',
    ccmRouteListName => '1.3.6.1.4.1.9.9.156.1.10.8',
    ccmGatewayPhysIfIndex => '1.3.6.1.4.1.9.9.156.1.10.9',
    ccmGatewayPhysIfL2Status => '1.3.6.1.4.1.9.9.156.1.10.10',
    ccmMaliCallCalledPartyName => '1.3.6.1.4.1.9.9.156.1.10.11',
    ccmMaliCallCalledPartyNumber => '1.3.6.1.4.1.9.9.156.1.10.12',
    ccmMaliCallCalledDeviceName => '1.3.6.1.4.1.9.9.156.1.10.13',
    ccmMaliCallCallingPartyName => '1.3.6.1.4.1.9.9.156.1.10.14',
    ccmMaliCallCallingPartyNumber => '1.3.6.1.4.1.9.9.156.1.10.15',
    ccmMaliCallCallingDeviceName => '1.3.6.1.4.1.9.9.156.1.10.16',
    ccmMaliCallTime => '1.3.6.1.4.1.9.9.156.1.10.17',
    ccmQualityRprtSourceDevName => '1.3.6.1.4.1.9.9.156.1.10.18',
    ccmQualityRprtClusterId => '1.3.6.1.4.1.9.9.156.1.10.19',
    ccmQualityRprtCategory => '1.3.6.1.4.1.9.9.156.1.10.20',
    ccmQualityRprtReasonCode => '1.3.6.1.4.1.9.9.156.1.10.21',
    ccmQualityRprtTime => '1.3.6.1.4.1.9.9.156.1.10.22',
    ccmTLSDevName => '1.3.6.1.4.1.9.9.156.1.10.23',
    ccmTLSDevInetAddressType => '1.3.6.1.4.1.9.9.156.1.10.24',
    ccmTLSDevInetAddress => '1.3.6.1.4.1.9.9.156.1.10.25',
    ccmTLSConnFailTime => '1.3.6.1.4.1.9.9.156.1.10.26',
    ccmTLSConnectionFailReasonCode => '1.3.6.1.4.1.9.9.156.1.10.27',
    ccmGatewayRegFailCauseCode => '1.3.6.1.4.1.9.9.156.1.10.28',
    ccmH323DeviceTable => '1.3.6.1.4.1.9.9.156.1.11.1',
    ccmH323DeviceEntry => '1.3.6.1.4.1.9.9.156.1.11.1.1',
    ccmH323DevIndex => '1.3.6.1.4.1.9.9.156.1.11.1.1.1',
    ccmH323DevName => '1.3.6.1.4.1.9.9.156.1.11.1.1.2',
    ccmH323DevProductId => '1.3.6.1.4.1.9.9.156.1.11.1.1.3',
    ccmH323DevDescription => '1.3.6.1.4.1.9.9.156.1.11.1.1.4',
    ccmH323DevInetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.5',
    ccmH323DevInetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.6',
    ccmH323DevCnfgGKInetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.7',
    ccmH323DevCnfgGKInetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.8',
    ccmH323DevAltGK1InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.9',
    ccmH323DevAltGK1InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.10',
    ccmH323DevAltGK2InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.11',
    ccmH323DevAltGK2InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.12',
    ccmH323DevAltGK3InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.13',
    ccmH323DevAltGK3InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.14',
    ccmH323DevAltGK4InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.15',
    ccmH323DevAltGK4InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.16',
    ccmH323DevAltGK5InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.17',
    ccmH323DevAltGK5InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.18',
    ccmH323DevActGKInetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.19',
    ccmH323DevActGKInetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.20',
    ccmH323DevStatus => '1.3.6.1.4.1.9.9.156.1.11.1.1.21',
    ccmH323DevStatusReason => '1.3.6.1.4.1.9.9.156.1.11.1.1.22',
    ccmH323DevTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.11.1.1.23',
    ccmH323DevTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.11.1.1.24',
    ccmH323DevRmtCM1InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.25',
    ccmH323DevRmtCM1InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.26',
    ccmH323DevRmtCM2InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.27',
    ccmH323DevRmtCM2InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.28',
    ccmH323DevRmtCM3InetAddressType => '1.3.6.1.4.1.9.9.156.1.11.1.1.29',
    ccmH323DevRmtCM3InetAddress => '1.3.6.1.4.1.9.9.156.1.11.1.1.30',
    ccmH323DevProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.11.1.1.31',
    ccmH323DevUnregReason => '1.3.6.1.4.1.9.9.156.1.11.1.1.32',
    ccmH323DevRegFailReason => '1.3.6.1.4.1.9.9.156.1.11.1.1.33',
    ccmVoiceMailDeviceTable => '1.3.6.1.4.1.9.9.156.1.12.1',
    ccmVoiceMailDeviceDirNumTable => '1.3.6.1.4.1.9.9.156.1.12.2',
    ccmVoiceMailDeviceEntry => '1.3.6.1.4.1.9.9.156.1.12.1.1',
    ccmVMailDevIndex => '1.3.6.1.4.1.9.9.156.1.12.1.1.1',
    ccmVMailDevName => '1.3.6.1.4.1.9.9.156.1.12.1.1.2',
    ccmVMailDevProductId => '1.3.6.1.4.1.9.9.156.1.12.1.1.3',
    ccmVMailDevDescription => '1.3.6.1.4.1.9.9.156.1.12.1.1.4',
    ccmVMailDevStatus => '1.3.6.1.4.1.9.9.156.1.12.1.1.5',
    ccmVMailDevInetAddressType => '1.3.6.1.4.1.9.9.156.1.12.1.1.6',
    ccmVMailDevInetAddress => '1.3.6.1.4.1.9.9.156.1.12.1.1.7',
    ccmVMailDevStatusReason => '1.3.6.1.4.1.9.9.156.1.12.1.1.8',
    ccmVMailDevTimeLastStatusUpdt => '1.3.6.1.4.1.9.9.156.1.12.1.1.9',
    ccmVMailDevTimeLastRegistered => '1.3.6.1.4.1.9.9.156.1.12.1.1.10',
    ccmVMailDevProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.12.1.1.11',
    ccmVMailDevUnregReason => '1.3.6.1.4.1.9.9.156.1.12.1.1.12',
    ccmVMailDevRegFailReason => '1.3.6.1.4.1.9.9.156.1.12.1.1.13',
    ccmVoiceMailDeviceDirNumEntry => '1.3.6.1.4.1.9.9.156.1.12.2.1',
    ccmVMailDevDirNumIndex => '1.3.6.1.4.1.9.9.156.1.12.2.1.1',
    ccmVMailDevDirNum => '1.3.6.1.4.1.9.9.156.1.12.2.1.2',
    ccmQualityReportAlarmEnable => '1.3.6.1.4.1.9.9.156.1.13.1',
    ccmSIPDeviceTable => '1.3.6.1.4.1.9.9.156.1.14.1',
    ccmSIPDeviceEntry => '1.3.6.1.4.1.9.9.156.1.14.1.1',
    ccmSIPDevIndex => '1.3.6.1.4.1.9.9.156.1.14.1.1.1',
    ccmSIPDevName => '1.3.6.1.4.1.9.9.156.1.14.1.1.2',
    ccmSIPDevProductTypeIndex => '1.3.6.1.4.1.9.9.156.1.14.1.1.3',
    ccmSIPDevDescription => '1.3.6.1.4.1.9.9.156.1.14.1.1.4',
    ccmSIPDevInetAddressType => '1.3.6.1.4.1.9.9.156.1.14.1.1.5',
    ccmSIPDevInetAddress => '1.3.6.1.4.1.9.9.156.1.14.1.1.6',
    ccmSIPInTransportProtocolType => '1.3.6.1.4.1.9.9.156.1.14.1.1.7',
    ccmSIPInPortNumber => '1.3.6.1.4.1.9.9.156.1.14.1.1.8',
    ccmSIPOutTransportProtocolType => '1.3.6.1.4.1.9.9.156.1.14.1.1.9',
    ccmSIPOutPortNumber => '1.3.6.1.4.1.9.9.156.1.14.1.1.10',
    ccmSIPDevInetAddressIPv4 => '1.3.6.1.4.1.9.9.156.1.14.1.1.11',
    ccmSIPDevInetAddressIPv6 => '1.3.6.1.4.1.9.9.156.1.14.1.1.12',
    ccmMIBNotifications => '1.3.6.1.4.1.9.9.156.2',
    ciscoCcmMIBCompliances => '1.3.6.1.4.1.9.9.156.3.1',
    ciscoCcmMIBGroups => '1.3.6.1.4.1.9.9.156.3.2',
    ciscoCcmMIBCompliance => '1.3.6.1.4.1.9.9.156.3.1.1',
    ciscoCcmMIBComplianceRev1 => '1.3.6.1.4.1.9.9.156.3.1.2',
    ciscoCcmMIBComplianceRev2 => '1.3.6.1.4.1.9.9.156.3.1.3',
    ciscoCcmMIBComplianceRev3 => '1.3.6.1.4.1.9.9.156.3.1.4',
    ciscoCcmMIBComplianceRev4 => '1.3.6.1.4.1.9.9.156.3.1.5',
    ciscoCcmMIBComplianceRev5 => '1.3.6.1.4.1.9.9.156.3.1.6',
    ciscoCcmMIBComplianceRev6 => '1.3.6.1.4.1.9.9.156.3.1.7',
    ciscoCcmMIBComplianceRev7 => '1.3.6.1.4.1.9.9.156.3.1.8',
    ccmInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.1',
    ccmPhoneInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.2',
    ccmGatewayInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.3',
    ccmInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.4',
    ccmPhoneInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.5',
    ccmGatewayInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.6',
    ccmMediaDeviceInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.7',
    ccmGatekeeperInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.8',
    ccmCTIDeviceInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.9',
    ccmNotificationsInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.10',
    ccmInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.12',
    ccmPhoneInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.13',
    ccmGatewayInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.14',
    ccmMediaDeviceInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.15',
    ccmCTIDeviceInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.16',
    ccmH323DeviceInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.17',
    ccmVoiceMailDeviceInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.18',
    ccmNotificationsInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.19',
    ccmInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.20',
    ccmNotificationsInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.21',
    ccmSIPDeviceInfoGroup => '1.3.6.1.4.1.9.9.156.3.2.23',
    ccmPhoneInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.24',
    ccmGatewayInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.25',
    ccmMediaDeviceInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.26',
    ccmCTIDeviceInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.27',
    ccmH323DeviceInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.28',
    ccmVoiceMailDeviceInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.29',
    ccmPhoneInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.30',
    ccmSIPDeviceInfoGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.31',
    ccmNotificationsInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.32',
    ccmInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.34',
    ccmPhoneInfoGroupRev5 => '1.3.6.1.4.1.9.9.156.3.2.35',
    ccmMediaDeviceInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.36',
    ccmSIPDeviceInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.37',
    ccmNotificationsInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.38',
    ccmH323DeviceInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.39',
    ccmCTIDeviceInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.40',
    ccmPhoneInfoGroupRev6 => '1.3.6.1.4.1.9.9.156.3.2.41',
    ccmNotificationsInfoGroupRev5 => '1.3.6.1.4.1.9.9.156.3.2.42',
    ccmGatewayInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.43',
    ccmMediaDeviceInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.44',
    ccmCTIDeviceInfoGroupRev4 => '1.3.6.1.4.1.9.9.156.3.2.45',
    ccmH323DeviceInfoGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.46',
    ccmVoiceMailDeviceInfoGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.47',
    ccmNotificationsGroup => '1.3.6.1.4.1.9.9.156.3.2.11',
    ccmNotificationsGroupRev1 => '1.3.6.1.4.1.9.9.156.3.2.22',
    ccmNotificationsGroupRev2 => '1.3.6.1.4.1.9.9.156.3.2.33',
    ccmNotificationsGroupRev3 => '1.3.6.1.4.1.9.9.156.3.2.48',
  },
  'CISCO-IETF-NAT-MIB' => {
    ciscoNatMIBObjects => '1.3.6.1.4.1.9.10.77.1',
    cnatConfig => '1.3.6.1.4.1.9.10.77.1.1',
    cnatBind => '1.3.6.1.4.1.9.10.77.1.2',
    cnatStatistics => '1.3.6.1.4.1.9.10.77.1.3',
    cnatConfig => '1.3.6.1.4.1.9.10.77.1.1',
    cnatConfTable => '1.3.6.1.4.1.9.10.77.1.1.1',
    cnatConfEntry => '1.3.6.1.4.1.9.10.77.1.1.1.1',
    cnatConfName => '1.3.6.1.4.1.9.10.77.1.1.1.1.1',
    cnatConfServiceType => '1.3.6.1.4.1.9.10.77.1.1.1.1.2',
    cnatConfTimeoutIcmpIdle => '1.3.6.1.4.1.9.10.77.1.1.1.1.3',
    cnatConfTimeoutUdpIdle => '1.3.6.1.4.1.9.10.77.1.1.1.1.4',
    cnatConfTimeoutTcpIdle => '1.3.6.1.4.1.9.10.77.1.1.1.1.5',
    cnatConfTimeoutTcpNeg => '1.3.6.1.4.1.9.10.77.1.1.1.1.6',
    cnatConfTimeoutOther => '1.3.6.1.4.1.9.10.77.1.1.1.1.7',
    cnatConfMaxBindLeaseTime => '1.3.6.1.4.1.9.10.77.1.1.1.1.8',
    cnatConfMaxBindIdleTime => '1.3.6.1.4.1.9.10.77.1.1.1.1.9',
    cnatConfStorageType => '1.3.6.1.4.1.9.10.77.1.1.1.1.10',
    cnatConfStatus => '1.3.6.1.4.1.9.10.77.1.1.1.1.11',
    cnatConfStaticAddrMapTable => '1.3.6.1.4.1.9.10.77.1.1.2',
    cnatConfStaticAddrMapEntry => '1.3.6.1.4.1.9.10.77.1.1.2.1',
    cnatConfStaticAddrMapName => '1.3.6.1.4.1.9.10.77.1.1.2.1.1',
    cnatConfStaticAddrMapType => '1.3.6.1.4.1.9.10.77.1.1.2.1.2',
    cnatConfStaticLocalAddrFrom => '1.3.6.1.4.1.9.10.77.1.1.2.1.3',
    cnatConfStaticLocalAddrTo => '1.3.6.1.4.1.9.10.77.1.1.2.1.4',
    cnatConfStaticLocalPortFrom => '1.3.6.1.4.1.9.10.77.1.1.2.1.5',
    cnatConfStaticLocalPortTo => '1.3.6.1.4.1.9.10.77.1.1.2.1.6',
    cnatConfStaticGlobalAddrFrom => '1.3.6.1.4.1.9.10.77.1.1.2.1.7',
    cnatConfStaticGlobalAddrTo => '1.3.6.1.4.1.9.10.77.1.1.2.1.8',
    cnatConfStaticGlobalPortFrom => '1.3.6.1.4.1.9.10.77.1.1.2.1.9',
    cnatConfStaticGlobalPortTo => '1.3.6.1.4.1.9.10.77.1.1.2.1.10',
    cnatConfStaticProtocol => '1.3.6.1.4.1.9.10.77.1.1.2.1.11',
    cnatConfStaticAddrMapStorageType => '1.3.6.1.4.1.9.10.77.1.1.2.1.12',
    cnatConfStaticAddrMapStatus => '1.3.6.1.4.1.9.10.77.1.1.2.1.13',
    cnatConfDynAddrMapTable => '1.3.6.1.4.1.9.10.77.1.1.3',
    cnatConfDynAddrMapEntry => '1.3.6.1.4.1.9.10.77.1.1.3.1',
    cnatConfDynAddrMapName => '1.3.6.1.4.1.9.10.77.1.1.3.1.1',
    cnatConfDynAddressMapType => '1.3.6.1.4.1.9.10.77.1.1.3.1.2',
    cnatConfDynLocalAddrFrom => '1.3.6.1.4.1.9.10.77.1.1.3.1.3',
    cnatConfDynLocalAddrTo => '1.3.6.1.4.1.9.10.77.1.1.3.1.4',
    cnatConfDynLocalPortFrom => '1.3.6.1.4.1.9.10.77.1.1.3.1.5',
    cnatConfDynLocalPortTo => '1.3.6.1.4.1.9.10.77.1.1.3.1.6',
    cnatConfDynGlobalAddrFrom => '1.3.6.1.4.1.9.10.77.1.1.3.1.7',
    cnatConfDynGlobalAddrTo => '1.3.6.1.4.1.9.10.77.1.1.3.1.8',
    cnatConfDynGlobalPortFrom => '1.3.6.1.4.1.9.10.77.1.1.3.1.9',
    cnatConfDynGlobalPortTo => '1.3.6.1.4.1.9.10.77.1.1.3.1.10',
    cnatConfDynProtocol => '1.3.6.1.4.1.9.10.77.1.1.3.1.11',
    cnatConfDynAddrMapStorageType => '1.3.6.1.4.1.9.10.77.1.1.3.1.12',
    cnatConfDynAddrMapStatus => '1.3.6.1.4.1.9.10.77.1.1.3.1.13',
    cnatInterfaceTable => '1.3.6.1.4.1.9.10.77.1.1.4',
    cnatInterfaceEntry => '1.3.6.1.4.1.9.10.77.1.1.4.1',
    cnatInterfaceIndex => '1.3.6.1.4.1.9.10.77.1.1.4.1.1',
    cnatInterfaceRealm => '1.3.6.1.4.1.9.10.77.1.1.4.1.2',
    cnatInterfaceStorageType => '1.3.6.1.4.1.9.10.77.1.1.4.1.3',
    cnatInterfaceStatus => '1.3.6.1.4.1.9.10.77.1.1.4.1.4',
    cnatBind => '1.3.6.1.4.1.9.10.77.1.2',
    cnatAddrBindNumberOfEntries => '1.3.6.1.4.1.9.10.77.1.2.1.0',
    cnatAddrBindTable => '1.3.6.1.4.1.9.10.77.1.2.2',
    cnatAddrBindEntry => '1.3.6.1.4.1.9.10.77.1.2.2.1',
    cnatAddrBindLocalAddr => '1.3.6.1.4.1.9.10.77.1.2.2.1.1',
    cnatAddrBindGlobalAddr => '1.3.6.1.4.1.9.10.77.1.2.2.1.2',
    cnatAddrBindId => '1.3.6.1.4.1.9.10.77.1.2.2.1.3',
    cnatAddrBindDirection => '1.3.6.1.4.1.9.10.77.1.2.2.1.4',
    cnatAddrBindType => '1.3.6.1.4.1.9.10.77.1.2.2.1.5',
    cnatAddrBindConfName => '1.3.6.1.4.1.9.10.77.1.2.2.1.6',
    cnatAddrBindSessionCount => '1.3.6.1.4.1.9.10.77.1.2.2.1.7',
    cnatAddrBindCurrentIdleTime => '1.3.6.1.4.1.9.10.77.1.2.2.1.8',
    cnatAddrBindInTranslate => '1.3.6.1.4.1.9.10.77.1.2.2.1.9',
    cnatAddrBindOutTranslate => '1.3.6.1.4.1.9.10.77.1.2.2.1.10',
    cnatAddrPortBindNumberOfEntries => '1.3.6.1.4.1.9.10.77.1.2.3.0',
    cnatAddrPortBindTable => '1.3.6.1.4.1.9.10.77.1.2.4',
    cnatAddrPortBindEntry => '1.3.6.1.4.1.9.10.77.1.2.4.1',
    cnatAddrPortBindLocalAddr => '1.3.6.1.4.1.9.10.77.1.2.4.1.1',
    cnatAddrPortBindLocalPort => '1.3.6.1.4.1.9.10.77.1.2.4.1.2',
    cnatAddrPortBindProtocol => '1.3.6.1.4.1.9.10.77.1.2.4.1.3',
    cnatAddrPortBindGlobalAddr => '1.3.6.1.4.1.9.10.77.1.2.4.1.4',
    cnatAddrPortBindGlobalPort => '1.3.6.1.4.1.9.10.77.1.2.4.1.5',
    cnatAddrPortBindId => '1.3.6.1.4.1.9.10.77.1.2.4.1.6',
    cnatAddrPortBindDirection => '1.3.6.1.4.1.9.10.77.1.2.4.1.7',
    cnatAddrPortBindType => '1.3.6.1.4.1.9.10.77.1.2.4.1.8',
    cnatAddrPortBindConfName => '1.3.6.1.4.1.9.10.77.1.2.4.1.9',
    cnatAddrPortBindSessionCount => '1.3.6.1.4.1.9.10.77.1.2.4.1.10',
    cnatAddrPortBindCurrentIdleTime => '1.3.6.1.4.1.9.10.77.1.2.4.1.11',
    cnatAddrPortBindInTranslate => '1.3.6.1.4.1.9.10.77.1.2.4.1.12',
    cnatAddrPortBindOutTranslate => '1.3.6.1.4.1.9.10.77.1.2.4.1.13',
    cnatSessionTable => '1.3.6.1.4.1.9.10.77.1.2.5',
    cnatSessionEntry => '1.3.6.1.4.1.9.10.77.1.2.5.1',
    cnatSessionBindId => '1.3.6.1.4.1.9.10.77.1.2.5.1.1',
    cnatSessionId => '1.3.6.1.4.1.9.10.77.1.2.5.1.2',
    cnatSessionDirection => '1.3.6.1.4.1.9.10.77.1.2.5.1.3',
    cnatSessionUpTime => '1.3.6.1.4.1.9.10.77.1.2.5.1.4',
    cnatSessionProtocolType => '1.3.6.1.4.1.9.10.77.1.2.5.1.5',
    cnatSessionOrigPrivateAddr => '1.3.6.1.4.1.9.10.77.1.2.5.1.6',
    cnatSessionTransPrivateAddr => '1.3.6.1.4.1.9.10.77.1.2.5.1.7',
    cnatSessionOrigPrivatePort => '1.3.6.1.4.1.9.10.77.1.2.5.1.8',
    cnatSessionTransPrivatePort => '1.3.6.1.4.1.9.10.77.1.2.5.1.9',
    cnatSessionOrigPublicAddr => '1.3.6.1.4.1.9.10.77.1.2.5.1.10',
    cnatSessionTransPublicAddr => '1.3.6.1.4.1.9.10.77.1.2.5.1.11',
    cnatSessionOrigPublicPort => '1.3.6.1.4.1.9.10.77.1.2.5.1.12',
    cnatSessionTransPublicPort => '1.3.6.1.4.1.9.10.77.1.2.5.1.13',
    cnatSessionCurrentIdletime => '1.3.6.1.4.1.9.10.77.1.2.5.1.14',
    cnatSessionSecondBindId => '1.3.6.1.4.1.9.10.77.1.2.5.1.15',
    cnatSessionInTranslate => '1.3.6.1.4.1.9.10.77.1.2.5.1.16',
    cnatSessionOutTranslate => '1.3.6.1.4.1.9.10.77.1.2.5.1.17',
    cnatStatistics => '1.3.6.1.4.1.9.10.77.1.3',
    cnatProtocolStatsTable => '1.3.6.1.4.1.9.10.77.1.3.1',
    cnatProtocolStatsEntry => '1.3.6.1.4.1.9.10.77.1.3.1.1',
    cnatProtocolStatsName => '1.3.6.1.4.1.9.10.77.1.3.1.1.1',
    cnatProtocolStatsNameDefinition => 'CISCO-IETF-NAT-MIB::NATProtocolType',
    cnatProtocolStatsInTranslate => '1.3.6.1.4.1.9.10.77.1.3.1.1.2',
    cnatProtocolStatsOutTranslate => '1.3.6.1.4.1.9.10.77.1.3.1.1.3',
    cnatProtocolStatsRejectCount => '1.3.6.1.4.1.9.10.77.1.3.1.1.4',
    cnatAddrMapStatsTable => '1.3.6.1.4.1.9.10.77.1.3.2',
    cnatAddrMapStatsEntry => '1.3.6.1.4.1.9.10.77.1.3.2.1',
    cnatAddrMapStatsConfName => '1.3.6.1.4.1.9.10.77.1.3.2.1.1',
    cnatAddrMapStatsMapName => '1.3.6.1.4.1.9.10.77.1.3.2.1.2',
    cnatAddrMapStatsInTranslate => '1.3.6.1.4.1.9.10.77.1.3.2.1.3',
    cnatAddrMapStatsOutTranslate => '1.3.6.1.4.1.9.10.77.1.3.2.1.4',
    cnatAddrMapStatsNoResource => '1.3.6.1.4.1.9.10.77.1.3.2.1.5',
    cnatAddrMapStatsAddrUsed => '1.3.6.1.4.1.9.10.77.1.3.2.1.6',
    cnatInterfaceStatsTable => '1.3.6.1.4.1.9.10.77.1.3.3',
    cnatInterfaceStatsEntry => '1.3.6.1.4.1.9.10.77.1.3.3.1',
    cnatInterfacePktsIn => '1.3.6.1.4.1.9.10.77.1.3.3.1.1',
    cnatInterfacePktsOut => '1.3.6.1.4.1.9.10.77.1.3.3.1.2',
    ciscoNatMIBNotificationPrefix => '1.3.6.1.4.1.9.10.77.2',
    ciscoNatMIBNotifications => '1.3.6.1.4.1.9.10.77.2.0',
    ciscoNatMIBConformance => '1.3.6.1.4.1.9.10.77.3',
    ciscoNatMIBCompliances => '1.3.6.1.4.1.9.10.77.3.1',
    ciscoNatMIBGroups => '1.3.6.1.4.1.9.10.77.3.2',
  },
  'CISCO-FEATURE-CONTROL-MIB' => {
    cfcFeatureCtrlTable => '1.3.6.1.4.1.9.9.377.1.1.1',
    cfcFeatureCtrlEntry => '1.3.6.1.4.1.9.9.377.1.1.1.1',
    cfcFeatureCtrlIndex => 'CISCO-FEATURE-CONTROL-MIB::CiscoOptionalFeature',
    cfcFeatureCtrlName => '1.3.6.1.4.1.9.9.377.1.1.1.1.2',
    cfcFeatureCtrlAction => 'CISCO-FEATURE-CONTROL-MIB::CiscoFeatureAction',
    cfcFeatureCtrlLastAction => 'CISCO-FEATURE-CONTROL-MIB::CiscoFeatureAction',
    cfcFeatureCtrlLastActionResult => 'CISCO-FEATURE-CONTROL-MIB::CiscoFeatureActionResult',
    cfcFeatureCtrlLastFailureReason => '1.3.6.1.4.1.9.9.377.1.1.1.1.6',
    cfcFeatureCtrlOpStatus => 'CISCO-FEATURE-CONTROL-MIB::CiscoFeatureStatus',
    cfcFeatureCtrlOpStatusReason => '1.3.6.1.4.1.9.9.377.1.1.1.1.8',
  },
  'CISCO-IPSEC-FLOW-MONITOR-MIB' => {
    enterprises => '1.3.6.1.4.1',
    cisco => '1.3.6.1.4.1.9',
    ciscoMgmt => '1.3.6.1.4.1.9.9',
    ciscoIpSecFlowMonitorMIB => '1.3.6.1.4.1.9.9.171',
    ciscoIpSecFlowMonitorMIBDefinition => {
      '1' => 'enabled',
      '2' => 'disabled',
    },
    cipSecMIBObjects => '1.3.6.1.4.1.9.9.171.1',
    cipSecLevels => '1.3.6.1.4.1.9.9.171.1.1',
    cipSecMibLevel => '1.3.6.1.4.1.9.9.171.1.1.1',
    cipSecPhaseOne => '1.3.6.1.4.1.9.9.171.1.2',
    cikeGlobalStats => '1.3.6.1.4.1.9.9.171.1.2.1',
    cikeGlobalActiveTunnels => '1.3.6.1.4.1.9.9.171.1.2.1.1',
    cikeGlobalPreviousTunnels => '1.3.6.1.4.1.9.9.171.1.2.1.2',
    cikeGlobalInOctets => '1.3.6.1.4.1.9.9.171.1.2.1.3',
    cikeGlobalInPkts => '1.3.6.1.4.1.9.9.171.1.2.1.4',
    cikeGlobalInDropPkts => '1.3.6.1.4.1.9.9.171.1.2.1.5',
    cikeGlobalInNotifys => '1.3.6.1.4.1.9.9.171.1.2.1.6',
    cikeGlobalInP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.1.7',
    cikeGlobalInP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.1.8',
    cikeGlobalInP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.1.9',
    cikeGlobalInP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.1.10',
    cikeGlobalOutOctets => '1.3.6.1.4.1.9.9.171.1.2.1.11',
    cikeGlobalOutPkts => '1.3.6.1.4.1.9.9.171.1.2.1.12',
    cikeGlobalOutDropPkts => '1.3.6.1.4.1.9.9.171.1.2.1.13',
    cikeGlobalOutNotifys => '1.3.6.1.4.1.9.9.171.1.2.1.14',
    cikeGlobalOutP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.1.15',
    cikeGlobalOutP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.1.16',
    cikeGlobalOutP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.1.17',
    cikeGlobalOutP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.1.18',
    cikeGlobalInitTunnels => '1.3.6.1.4.1.9.9.171.1.2.1.19',
    cikeGlobalInitTunnelFails => '1.3.6.1.4.1.9.9.171.1.2.1.20',
    cikeGlobalRespTunnelFails => '1.3.6.1.4.1.9.9.171.1.2.1.21',
    cikeGlobalSysCapFails => '1.3.6.1.4.1.9.9.171.1.2.1.22',
    cikeGlobalAuthFails => '1.3.6.1.4.1.9.9.171.1.2.1.23',
    cikeGlobalDecryptFails => '1.3.6.1.4.1.9.9.171.1.2.1.24',
    cikeGlobalHashValidFails => '1.3.6.1.4.1.9.9.171.1.2.1.25',
    cikeGlobalNoSaFails => '1.3.6.1.4.1.9.9.171.1.2.1.26',
    cikePeerTable => '1.3.6.1.4.1.9.9.171.1.2.2',
    cikePeerEntry => '1.3.6.1.4.1.9.9.171.1.2.2.1',
    cikePeerLocalType => '1.3.6.1.4.1.9.9.171.1.2.2.1.1',
    cikePeerLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikePeerLocalValue => '1.3.6.1.4.1.9.9.171.1.2.2.1.2',
    cikePeerRemoteType => '1.3.6.1.4.1.9.9.171.1.2.2.1.3',
    cikePeerRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikePeerRemoteValue => '1.3.6.1.4.1.9.9.171.1.2.2.1.4',
    cikePeerIntIndex => '1.3.6.1.4.1.9.9.171.1.2.2.1.5',
    cikePeerLocalAddr => '1.3.6.1.4.1.9.9.171.1.2.2.1.6',
    cikePeerRemoteAddr => '1.3.6.1.4.1.9.9.171.1.2.2.1.7',
    cikePeerActiveTime => '1.3.6.1.4.1.9.9.171.1.2.2.1.8',
    cikePeerActiveTunnelIndex => '1.3.6.1.4.1.9.9.171.1.2.2.1.9',
    cikeTunnelTable => '1.3.6.1.4.1.9.9.171.1.2.3',
    cikeTunnelEntry => '1.3.6.1.4.1.9.9.171.1.2.3.1',
    cikeTunIndex => '1.3.6.1.4.1.9.9.171.1.2.3.1.1',
    cikeTunLocalType => '1.3.6.1.4.1.9.9.171.1.2.3.1.2',
    cikeTunLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeTunLocalValue => '1.3.6.1.4.1.9.9.171.1.2.3.1.3',
    cikeTunLocalAddr => '1.3.6.1.4.1.9.9.171.1.2.3.1.4',
    cikeTunLocalName => '1.3.6.1.4.1.9.9.171.1.2.3.1.5',
    cikeTunRemoteType => '1.3.6.1.4.1.9.9.171.1.2.3.1.6',
    cikeTunRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeTunRemoteValue => '1.3.6.1.4.1.9.9.171.1.2.3.1.7',
    cikeTunRemoteAddr => '1.3.6.1.4.1.9.9.171.1.2.3.1.8',
    cikeTunRemoteName => '1.3.6.1.4.1.9.9.171.1.2.3.1.9',
    cikeTunNegoMode => '1.3.6.1.4.1.9.9.171.1.2.3.1.10',
    cikeTunNegoModeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeNegoMode',
    cikeTunDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.2.3.1.11',
    cikeTunDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cikeTunEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.2.3.1.12',
    cikeTunEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cikeTunHashAlgo => '1.3.6.1.4.1.9.9.171.1.2.3.1.13',
    cikeTunHashAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeHashAlgo',
    cikeTunAuthMethod => '1.3.6.1.4.1.9.9.171.1.2.3.1.14',
    cikeTunAuthMethodDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeAuthMethod',
    cikeTunLifeTime => '1.3.6.1.4.1.9.9.171.1.2.3.1.15',
    cikeTunActiveTime => '1.3.6.1.4.1.9.9.171.1.2.3.1.16',
    cikeTunSaRefreshThreshold => '1.3.6.1.4.1.9.9.171.1.2.3.1.17',
    cikeTunTotalRefreshes => '1.3.6.1.4.1.9.9.171.1.2.3.1.18',
    cikeTunInOctets => '1.3.6.1.4.1.9.9.171.1.2.3.1.19',
    cikeTunInPkts => '1.3.6.1.4.1.9.9.171.1.2.3.1.20',
    cikeTunInDropPkts => '1.3.6.1.4.1.9.9.171.1.2.3.1.21',
    cikeTunInNotifys => '1.3.6.1.4.1.9.9.171.1.2.3.1.22',
    cikeTunInP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.3.1.23',
    cikeTunInP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.3.1.24',
    cikeTunInP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.3.1.25',
    cikeTunInP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.3.1.26',
    cikeTunOutOctets => '1.3.6.1.4.1.9.9.171.1.2.3.1.27',
    cikeTunOutPkts => '1.3.6.1.4.1.9.9.171.1.2.3.1.28',
    cikeTunOutDropPkts => '1.3.6.1.4.1.9.9.171.1.2.3.1.29',
    cikeTunOutNotifys => '1.3.6.1.4.1.9.9.171.1.2.3.1.30',
    cikeTunOutP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.3.1.31',
    cikeTunOutP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.3.1.32',
    cikeTunOutP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.3.1.33',
    cikeTunOutP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.3.1.34',
    cikeTunStatus => '1.3.6.1.4.1.9.9.171.1.2.3.1.35',
    cikeTunStatusDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TunnelStatus',
    cikePeerCorrTable => '1.3.6.1.4.1.9.9.171.1.2.4',
    cikePeerCorrEntry => '1.3.6.1.4.1.9.9.171.1.2.4.1',
    cikePeerCorrLocalType => '1.3.6.1.4.1.9.9.171.1.2.4.1.1',
    cikePeerCorrLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikePeerCorrLocalValue => '1.3.6.1.4.1.9.9.171.1.2.4.1.2',
    cikePeerCorrRemoteType => '1.3.6.1.4.1.9.9.171.1.2.4.1.3',
    cikePeerCorrRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikePeerCorrRemoteValue => '1.3.6.1.4.1.9.9.171.1.2.4.1.4',
    cikePeerCorrIntIndex => '1.3.6.1.4.1.9.9.171.1.2.4.1.5',
    cikePeerCorrSeqNum => '1.3.6.1.4.1.9.9.171.1.2.4.1.6',
    cikePeerCorrIpSecTunIndex => '1.3.6.1.4.1.9.9.171.1.2.4.1.7',
    cikePhase1GWStatsTable => '1.3.6.1.4.1.9.9.171.1.2.5',
    cikePhase1GWStatsEntry => '1.3.6.1.4.1.9.9.171.1.2.5.1',
    cikePhase1GWActiveTunnels => '1.3.6.1.4.1.9.9.171.1.2.5.1.1',
    cikePhase1GWPreviousTunnels => '1.3.6.1.4.1.9.9.171.1.2.5.1.2',
    cikePhase1GWInOctets => '1.3.6.1.4.1.9.9.171.1.2.5.1.3',
    cikePhase1GWInPkts => '1.3.6.1.4.1.9.9.171.1.2.5.1.4',
    cikePhase1GWInDropPkts => '1.3.6.1.4.1.9.9.171.1.2.5.1.5',
    cikePhase1GWInNotifys => '1.3.6.1.4.1.9.9.171.1.2.5.1.6',
    cikePhase1GWInP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.5.1.7',
    cikePhase1GWInP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.5.1.8',
    cikePhase1GWInP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.5.1.9',
    cikePhase1GWInP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.5.1.10',
    cikePhase1GWOutOctets => '1.3.6.1.4.1.9.9.171.1.2.5.1.11',
    cikePhase1GWOutPkts => '1.3.6.1.4.1.9.9.171.1.2.5.1.12',
    cikePhase1GWOutDropPkts => '1.3.6.1.4.1.9.9.171.1.2.5.1.13',
    cikePhase1GWOutNotifys => '1.3.6.1.4.1.9.9.171.1.2.5.1.14',
    cikePhase1GWOutP2Exchgs => '1.3.6.1.4.1.9.9.171.1.2.5.1.15',
    cikePhase1GWOutP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.2.5.1.16',
    cikePhase1GWOutP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.2.5.1.17',
    cikePhase1GWOutP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.2.5.1.18',
    cikePhase1GWInitTunnels => '1.3.6.1.4.1.9.9.171.1.2.5.1.19',
    cikePhase1GWInitTunnelFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.20',
    cikePhase1GWRespTunnelFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.21',
    cikePhase1GWSysCapFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.22',
    cikePhase1GWAuthFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.23',
    cikePhase1GWDecryptFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.24',
    cikePhase1GWHashValidFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.25',
    cikePhase1GWNoSaFails => '1.3.6.1.4.1.9.9.171.1.2.5.1.26',
    cipSecPhaseTwo => '1.3.6.1.4.1.9.9.171.1.3',
    cipSecGlobalStats => '1.3.6.1.4.1.9.9.171.1.3.1',
    cipSecGlobalActiveTunnels => '1.3.6.1.4.1.9.9.171.1.3.1.1',
    cipSecGlobalPreviousTunnels => '1.3.6.1.4.1.9.9.171.1.3.1.2',
    cipSecGlobalInOctets => '1.3.6.1.4.1.9.9.171.1.3.1.3',
    cipSecGlobalHcInOctets => '1.3.6.1.4.1.9.9.171.1.3.1.4',
    cipSecGlobalInOctWraps => '1.3.6.1.4.1.9.9.171.1.3.1.5',
    cipSecGlobalInDecompOctets => '1.3.6.1.4.1.9.9.171.1.3.1.6',
    cipSecGlobalHcInDecompOctets => '1.3.6.1.4.1.9.9.171.1.3.1.7',
    cipSecGlobalInDecompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.1.8',
    cipSecGlobalInPkts => '1.3.6.1.4.1.9.9.171.1.3.1.9',
    cipSecGlobalInDrops => '1.3.6.1.4.1.9.9.171.1.3.1.10',
    cipSecGlobalInReplayDrops => '1.3.6.1.4.1.9.9.171.1.3.1.11',
    cipSecGlobalInAuths => '1.3.6.1.4.1.9.9.171.1.3.1.12',
    cipSecGlobalInAuthFails => '1.3.6.1.4.1.9.9.171.1.3.1.13',
    cipSecGlobalInDecrypts => '1.3.6.1.4.1.9.9.171.1.3.1.14',
    cipSecGlobalInDecryptFails => '1.3.6.1.4.1.9.9.171.1.3.1.15',
    cipSecGlobalOutOctets => '1.3.6.1.4.1.9.9.171.1.3.1.16',
    cipSecGlobalHcOutOctets => '1.3.6.1.4.1.9.9.171.1.3.1.17',
    cipSecGlobalOutOctWraps => '1.3.6.1.4.1.9.9.171.1.3.1.18',
    cipSecGlobalOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.3.1.19',
    cipSecGlobalHcOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.3.1.20',
    cipSecGlobalOutUncompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.1.21',
    cipSecGlobalOutPkts => '1.3.6.1.4.1.9.9.171.1.3.1.22',
    cipSecGlobalOutDrops => '1.3.6.1.4.1.9.9.171.1.3.1.23',
    cipSecGlobalOutAuths => '1.3.6.1.4.1.9.9.171.1.3.1.24',
    cipSecGlobalOutAuthFails => '1.3.6.1.4.1.9.9.171.1.3.1.25',
    cipSecGlobalOutEncrypts => '1.3.6.1.4.1.9.9.171.1.3.1.26',
    cipSecGlobalOutEncryptFails => '1.3.6.1.4.1.9.9.171.1.3.1.27',
    cipSecGlobalProtocolUseFails => '1.3.6.1.4.1.9.9.171.1.3.1.28',
    cipSecGlobalNoSaFails => '1.3.6.1.4.1.9.9.171.1.3.1.29',
    cipSecGlobalSysCapFails => '1.3.6.1.4.1.9.9.171.1.3.1.30',
    cipSecTunnelTable => '1.3.6.1.4.1.9.9.171.1.3.2',
    cipSecTunnelEntry => '1.3.6.1.4.1.9.9.171.1.3.2.1',
    cipSecTunIndex => '1.3.6.1.4.1.9.9.171.1.3.2.1.1',
    cipSecTunIkeTunnelIndex => '1.3.6.1.4.1.9.9.171.1.3.2.1.2',
    cipSecTunIkeTunnelAlive => '1.3.6.1.4.1.9.9.171.1.3.2.1.3',
    cipSecTunLocalAddr => '1.3.6.1.4.1.9.9.171.1.3.2.1.4',
    cipSecTunRemoteAddr => '1.3.6.1.4.1.9.9.171.1.3.2.1.5',
    cipSecTunKeyType => '1.3.6.1.4.1.9.9.171.1.3.2.1.6',
    cipSecTunKeyTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::KeyType',
    cipSecTunEncapMode => '1.3.6.1.4.1.9.9.171.1.3.2.1.7',
    cipSecTunEncapModeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncapMode',
    cipSecTunLifeSize => '1.3.6.1.4.1.9.9.171.1.3.2.1.8',
    cipSecTunLifeTime => '1.3.6.1.4.1.9.9.171.1.3.2.1.9',
    cipSecTunActiveTime => '1.3.6.1.4.1.9.9.171.1.3.2.1.10',
    cipSecTunSaLifeSizeThreshold => '1.3.6.1.4.1.9.9.171.1.3.2.1.11',
    cipSecTunSaLifeTimeThreshold => '1.3.6.1.4.1.9.9.171.1.3.2.1.12',
    cipSecTunTotalRefreshes => '1.3.6.1.4.1.9.9.171.1.3.2.1.13',
    cipSecTunExpiredSaInstances => '1.3.6.1.4.1.9.9.171.1.3.2.1.14',
    cipSecTunCurrentSaInstances => '1.3.6.1.4.1.9.9.171.1.3.2.1.15',
    cipSecTunInSaDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.3.2.1.16',
    cipSecTunInSaDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cipSecTunInSaEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.17',
    cipSecTunInSaEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cipSecTunInSaAhAuthAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.18',
    cipSecTunInSaAhAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunInSaEspAuthAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.19',
    cipSecTunInSaEspAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunInSaDecompAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.20',
    cipSecTunInSaDecompAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::CompAlgo',
    cipSecTunOutSaDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.3.2.1.21',
    cipSecTunOutSaDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cipSecTunOutSaEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.22',
    cipSecTunOutSaEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cipSecTunOutSaAhAuthAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.23',
    cipSecTunOutSaAhAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunOutSaEspAuthAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.24',
    cipSecTunOutSaEspAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunOutSaCompAlgo => '1.3.6.1.4.1.9.9.171.1.3.2.1.25',
    cipSecTunOutSaCompAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::CompAlgo',
    cipSecTunInOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.26',
    cipSecTunHcInOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.27',
    cipSecTunInOctWraps => '1.3.6.1.4.1.9.9.171.1.3.2.1.28',
    cipSecTunInDecompOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.29',
    cipSecTunHcInDecompOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.30',
    cipSecTunInDecompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.2.1.31',
    cipSecTunInPkts => '1.3.6.1.4.1.9.9.171.1.3.2.1.32',
    cipSecTunInDropPkts => '1.3.6.1.4.1.9.9.171.1.3.2.1.33',
    cipSecTunInReplayDropPkts => '1.3.6.1.4.1.9.9.171.1.3.2.1.34',
    cipSecTunInAuths => '1.3.6.1.4.1.9.9.171.1.3.2.1.35',
    cipSecTunInAuthFails => '1.3.6.1.4.1.9.9.171.1.3.2.1.36',
    cipSecTunInDecrypts => '1.3.6.1.4.1.9.9.171.1.3.2.1.37',
    cipSecTunInDecryptFails => '1.3.6.1.4.1.9.9.171.1.3.2.1.38',
    cipSecTunOutOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.39',
    cipSecTunHcOutOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.40',
    cipSecTunOutOctWraps => '1.3.6.1.4.1.9.9.171.1.3.2.1.41',
    cipSecTunOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.42',
    cipSecTunHcOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.3.2.1.43',
    cipSecTunOutUncompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.2.1.44',
    cipSecTunOutPkts => '1.3.6.1.4.1.9.9.171.1.3.2.1.45',
    cipSecTunOutDropPkts => '1.3.6.1.4.1.9.9.171.1.3.2.1.46',
    cipSecTunOutAuths => '1.3.6.1.4.1.9.9.171.1.3.2.1.47',
    cipSecTunOutAuthFails => '1.3.6.1.4.1.9.9.171.1.3.2.1.48',
    cipSecTunOutEncrypts => '1.3.6.1.4.1.9.9.171.1.3.2.1.49',
    cipSecTunOutEncryptFails => '1.3.6.1.4.1.9.9.171.1.3.2.1.50',
    cipSecTunStatus => '1.3.6.1.4.1.9.9.171.1.3.2.1.51',
    cipSecTunStatusDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TunnelStatus',
    cipSecEndPtTable => '1.3.6.1.4.1.9.9.171.1.3.3',
    cipSecEndPtEntry => '1.3.6.1.4.1.9.9.171.1.3.3.1',
    cipSecEndPtIndex => '1.3.6.1.4.1.9.9.171.1.3.3.1.1',
    cipSecEndPtLocalName => '1.3.6.1.4.1.9.9.171.1.3.3.1.2',
    cipSecEndPtLocalType => '1.3.6.1.4.1.9.9.171.1.3.3.1.3',
    cipSecEndPtLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EndPtType',
    cipSecEndPtLocalAddr1 => '1.3.6.1.4.1.9.9.171.1.3.3.1.4',
    cipSecEndPtLocalAddr2 => '1.3.6.1.4.1.9.9.171.1.3.3.1.5',
    cipSecEndPtLocalProtocol => '1.3.6.1.4.1.9.9.171.1.3.3.1.6',
    cipSecEndPtLocalPort => '1.3.6.1.4.1.9.9.171.1.3.3.1.7',
    cipSecEndPtRemoteName => '1.3.6.1.4.1.9.9.171.1.3.3.1.8',
    cipSecEndPtRemoteType => '1.3.6.1.4.1.9.9.171.1.3.3.1.9',
    cipSecEndPtRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EndPtType',
    cipSecEndPtRemoteAddr1 => '1.3.6.1.4.1.9.9.171.1.3.3.1.10',
    cipSecEndPtRemoteAddr2 => '1.3.6.1.4.1.9.9.171.1.3.3.1.11',
    cipSecEndPtRemoteProtocol => '1.3.6.1.4.1.9.9.171.1.3.3.1.12',
    cipSecEndPtRemotePort => '1.3.6.1.4.1.9.9.171.1.3.3.1.13',
    cipSecSpiTable => '1.3.6.1.4.1.9.9.171.1.3.4',
    cipSecSpiEntry => '1.3.6.1.4.1.9.9.171.1.3.4.1',
    cipSecSpiIndex => '1.3.6.1.4.1.9.9.171.1.3.4.1.1',
    cipSecSpiDirection => '1.3.6.1.4.1.9.9.171.1.3.4.1.2',
    cipSecSpiDirectionDefinition => {
      '1' => 'in',
      '2' => 'out',
    },
    cipSecSpiValue => '1.3.6.1.4.1.9.9.171.1.3.4.1.3',
    cipSecSpiProtocol => '1.3.6.1.4.1.9.9.171.1.3.4.1.4',
    cipSecSpiProtocolDefinition => {
      '1' => 'ah',
      '2' => 'esp',
      '3' => 'ipcomp',
    },
    cipSecSpiStatus => '1.3.6.1.4.1.9.9.171.1.3.4.1.5',
    cipSecSpiStatusDefinition => {
      '1' => 'active',
      '2' => 'expiring',
    },
    cipSecPhase2GWStatsTable => '1.3.6.1.4.1.9.9.171.1.3.5',
    cipSecPhase2GWStatsEntry => '1.3.6.1.4.1.9.9.171.1.3.5.1',
    cipSecPhase2GWActiveTunnels => '1.3.6.1.4.1.9.9.171.1.3.5.1.1',
    cipSecPhase2GWPreviousTunnels => '1.3.6.1.4.1.9.9.171.1.3.5.1.2',
    cipSecPhase2GWInOctets => '1.3.6.1.4.1.9.9.171.1.3.5.1.3',
    cipSecPhase2GWInOctWraps => '1.3.6.1.4.1.9.9.171.1.3.5.1.4',
    cipSecPhase2GWInDecompOctets => '1.3.6.1.4.1.9.9.171.1.3.5.1.5',
    cipSecPhase2GWInDecompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.5.1.6',
    cipSecPhase2GWInPkts => '1.3.6.1.4.1.9.9.171.1.3.5.1.7',
    cipSecPhase2GWInDrops => '1.3.6.1.4.1.9.9.171.1.3.5.1.8',
    cipSecPhase2GWInReplayDrops => '1.3.6.1.4.1.9.9.171.1.3.5.1.9',
    cipSecPhase2GWInAuths => '1.3.6.1.4.1.9.9.171.1.3.5.1.10',
    cipSecPhase2GWInAuthFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.11',
    cipSecPhase2GWInDecrypts => '1.3.6.1.4.1.9.9.171.1.3.5.1.12',
    cipSecPhase2GWInDecryptFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.13',
    cipSecPhase2GWOutOctets => '1.3.6.1.4.1.9.9.171.1.3.5.1.14',
    cipSecPhase2GWOutOctWraps => '1.3.6.1.4.1.9.9.171.1.3.5.1.15',
    cipSecPhase2GWOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.3.5.1.16',
    cipSecPhase2GWOutUncompOctWraps => '1.3.6.1.4.1.9.9.171.1.3.5.1.17',
    cipSecPhase2GWOutPkts => '1.3.6.1.4.1.9.9.171.1.3.5.1.18',
    cipSecPhase2GWOutDrops => '1.3.6.1.4.1.9.9.171.1.3.5.1.19',
    cipSecPhase2GWOutAuths => '1.3.6.1.4.1.9.9.171.1.3.5.1.20',
    cipSecPhase2GWOutAuthFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.21',
    cipSecPhase2GWOutEncrypts => '1.3.6.1.4.1.9.9.171.1.3.5.1.22',
    cipSecPhase2GWOutEncryptFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.23',
    cipSecPhase2GWProtocolUseFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.24',
    cipSecPhase2GWNoSaFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.25',
    cipSecPhase2GWSysCapFails => '1.3.6.1.4.1.9.9.171.1.3.5.1.26',
    cipSecHistory => '1.3.6.1.4.1.9.9.171.1.4',
    cipSecHistGlobal => '1.3.6.1.4.1.9.9.171.1.4.1',
    cipSecHistGlobalCntl => '1.3.6.1.4.1.9.9.171.1.4.1.1',
    cipSecHistTableSize => '1.3.6.1.4.1.9.9.171.1.4.1.1.1',
    cipSecHistCheckPoint => '1.3.6.1.4.1.9.9.171.1.4.1.1.2',
    cipSecHistCheckPointDefinition => {
      '1' => 'ready',
      '2' => 'checkPoint',
    },
    cipSecHistPhaseOne => '1.3.6.1.4.1.9.9.171.1.4.2',
    cikeTunnelHistTable => '1.3.6.1.4.1.9.9.171.1.4.2.1',
    cikeTunnelHistEntry => '1.3.6.1.4.1.9.9.171.1.4.2.1.1',
    cikeTunHistIndex => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.1',
    cikeTunHistTermReason => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.2',
    cikeTunHistTermReasonDefinition => {
      '1' => 'other',
      '2' => 'normal',
      '3' => 'operRequest',
      '4' => 'peerDelRequest',
      '5' => 'peerLost',
      '6' => 'localFailure',
      '7' => 'checkPointReg',
    },
    cikeTunHistActiveIndex => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.3',
    cikeTunHistPeerLocalType => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.4',
    cikeTunHistPeerLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeTunHistPeerLocalValue => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.5',
    cikeTunHistPeerIntIndex => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.6',
    cikeTunHistPeerRemoteType => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.7',
    cikeTunHistPeerRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeTunHistPeerRemoteValue => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.8',
    cikeTunHistLocalAddr => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.9',
    cikeTunHistLocalName => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.10',
    cikeTunHistRemoteAddr => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.11',
    cikeTunHistRemoteName => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.12',
    cikeTunHistNegoMode => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.13',
    cikeTunHistNegoModeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeNegoMode',
    cikeTunHistDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.14',
    cikeTunHistDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cikeTunHistEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.15',
    cikeTunHistEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cikeTunHistHashAlgo => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.16',
    cikeTunHistHashAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeHashAlgo',
    cikeTunHistAuthMethod => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.17',
    cikeTunHistAuthMethodDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkeAuthMethod',
    cikeTunHistLifeTime => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.18',
    cikeTunHistStartTime => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.19',
    cikeTunHistActiveTime => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.20',
    cikeTunHistTotalRefreshes => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.21',
    cikeTunHistTotalSas => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.22',
    cikeTunHistInOctets => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.23',
    cikeTunHistInPkts => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.24',
    cikeTunHistInDropPkts => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.25',
    cikeTunHistInNotifys => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.26',
    cikeTunHistInP2Exchgs => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.27',
    cikeTunHistInP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.28',
    cikeTunHistInP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.29',
    cikeTunHistInP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.30',
    cikeTunHistOutOctets => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.31',
    cikeTunHistOutPkts => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.32',
    cikeTunHistOutDropPkts => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.33',
    cikeTunHistOutNotifys => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.34',
    cikeTunHistOutP2Exchgs => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.35',
    cikeTunHistOutP2ExchgInvalids => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.36',
    cikeTunHistOutP2ExchgRejects => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.37',
    cikeTunHistOutP2SaDelRequests => '1.3.6.1.4.1.9.9.171.1.4.2.1.1.38',
    cipSecHistPhaseTwo => '1.3.6.1.4.1.9.9.171.1.4.3',
    cipSecTunnelHistTable => '1.3.6.1.4.1.9.9.171.1.4.3.1',
    cipSecTunnelHistEntry => '1.3.6.1.4.1.9.9.171.1.4.3.1.1',
    cipSecTunHistIndex => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.1',
    cipSecTunHistTermReason => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.2',
    cipSecTunHistTermReasonDefinition => {
      '1' => 'other',
      '2' => 'normal',
      '3' => 'operRequest',
      '4' => 'peerDelRequest',
      '5' => 'peerLost',
      '6' => 'seqNumRollOver',
      '7' => 'checkPointReq',
    },
    cipSecTunHistActiveIndex => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.3',
    cipSecTunHistLocalAddr => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.5',
    cipSecTunHistRemoteAddr => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.6',
    cipSecTunHistKeyType => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.7',
    cipSecTunHistKeyTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::KeyType',
    cipSecTunHistEncapMode => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.8',
    cipSecTunHistEncapModeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncapMode',
    cipSecTunHistLifeSize => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.9',
    cipSecTunHistLifeTime => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.10',
    cipSecTunHistStartTime => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.11',
    cipSecTunHistActiveTime => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.12',
    cipSecTunHistTotalRefreshes => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.13',
    cipSecTunHistTotalSas => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.14',
    cipSecTunHistInSaDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.15',
    cipSecTunHistInSaDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cipSecTunHistInSaEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.16',
    cipSecTunHistInSaEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cipSecTunHistInSaAhAuthAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.17',
    cipSecTunHistInSaAhAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunHistInSaEspAuthAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.18',
    cipSecTunHistInSaEspAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunHistInSaDecompAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.19',
    cipSecTunHistInSaDecompAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::CompAlgo',
    cipSecTunHistOutSaDiffHellmanGrp => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.20',
    cipSecTunHistOutSaDiffHellmanGrpDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::DiffHellmanGrp',
    cipSecTunHistOutSaEncryptAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.21',
    cipSecTunHistOutSaEncryptAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EncryptAlgo',
    cipSecTunHistOutSaAhAuthAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.22',
    cipSecTunHistOutSaAhAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunHistOutSaEspAuthAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.23',
    cipSecTunHistOutSaEspAuthAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::AuthAlgo',
    cipSecTunHistOutSaCompAlgo => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.24',
    cipSecTunHistOutSaCompAlgoDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::CompAlgo',
    cipSecTunHistInOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.25',
    cipSecTunHistHcInOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.26',
    cipSecTunHistInOctWraps => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.27',
    cipSecTunHistInDecompOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.28',
    cipSecTunHistHcInDecompOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.29',
    cipSecTunHistInDecompOctWraps => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.30',
    cipSecTunHistInPkts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.31',
    cipSecTunHistInDropPkts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.32',
    cipSecTunHistInReplayDropPkts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.33',
    cipSecTunHistInAuths => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.34',
    cipSecTunHistInAuthFails => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.35',
    cipSecTunHistInDecrypts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.36',
    cipSecTunHistInDecryptFails => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.37',
    cipSecTunHistOutOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.38',
    cipSecTunHistHcOutOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.39',
    cipSecTunHistOutOctWraps => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.40',
    cipSecTunHistOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.41',
    cipSecTunHistHcOutUncompOctets => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.42',
    cipSecTunHistOutUncompOctWraps => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.43',
    cipSecTunHistOutPkts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.44',
    cipSecTunHistOutDropPkts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.45',
    cipSecTunHistOutAuths => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.46',
    cipSecTunHistOutAuthFails => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.47',
    cipSecTunHistOutEncrypts => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.48',
    cipSecTunHistOutEncryptFails => '1.3.6.1.4.1.9.9.171.1.4.3.1.1.49',
    cipSecEndPtHistTable => '1.3.6.1.4.1.9.9.171.1.4.3.2',
    cipSecEndPtHistEntry => '1.3.6.1.4.1.9.9.171.1.4.3.2.1',
    cipSecEndPtHistIndex => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.1',
    cipSecEndPtHistTunIndex => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.2',
    cipSecEndPtHistActiveIndex => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.3',
    cipSecEndPtHistLocalName => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.4',
    cipSecEndPtHistLocalType => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.5',
    cipSecEndPtHistLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EndPtType',
    cipSecEndPtHistLocalAddr1 => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.6',
    cipSecEndPtHistLocalAddr2 => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.7',
    cipSecEndPtHistLocalProtocol => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.8',
    cipSecEndPtHistLocalPort => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.9',
    cipSecEndPtHistRemoteName => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.10',
    cipSecEndPtHistRemoteType => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.11',
    cipSecEndPtHistRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::EndPtType',
    cipSecEndPtHistRemoteAddr1 => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.12',
    cipSecEndPtHistRemoteAddr2 => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.13',
    cipSecEndPtHistRemoteProtocol => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.14',
    cipSecEndPtHistRemotePort => '1.3.6.1.4.1.9.9.171.1.4.3.2.1.15',
    cipSecFailures => '1.3.6.1.4.1.9.9.171.1.5',
    cipSecFailGlobal => '1.3.6.1.4.1.9.9.171.1.5.1',
    cipSecFailGlobalCntl => '1.3.6.1.4.1.9.9.171.1.5.1.1',
    cipSecFailTableSize => '1.3.6.1.4.1.9.9.171.1.5.1.1.1',
    cipSecFailPhaseOne => '1.3.6.1.4.1.9.9.171.1.5.2',
    cikeFailTable => '1.3.6.1.4.1.9.9.171.1.5.2.1',
    cikeFailEntry => '1.3.6.1.4.1.9.9.171.1.5.2.1.1',
    cikeFailIndex => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.1',
    cikeFailReason => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.2',
    cikeFailReasonDefinition => {
      '1' => 'other',
      '2' => 'peerDelRequest',
      '3' => 'peerLost',
      '4' => 'localFailure',
      '5' => 'authFailure',
      '6' => 'hashValidation',
      '7' => 'encryptFailure',
      '8' => 'internalError',
      '9' => 'sysCapExceeded',
      '10' => 'proposalFailure',
      '11' => 'peerCertUnavailable',
      '12' => 'peerCertNotValid',
      '13' => 'localCertExpired',
      '14' => 'crlFailure',
      '15' => 'peerEncodingError',
      '16' => 'nonExistentSa',
      '17' => 'operRequest',
    },
    cikeFailTime => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.3',
    cikeFailLocalType => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.4',
    cikeFailLocalTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeFailLocalValue => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.5',
    cikeFailRemoteType => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.6',
    cikeFailRemoteTypeDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::IkePeerType',
    cikeFailRemoteValue => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.7',
    cikeFailLocalAddr => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.8',
    cikeFailRemoteAddr => '1.3.6.1.4.1.9.9.171.1.5.2.1.1.9',
    cipSecFailPhaseTwo => '1.3.6.1.4.1.9.9.171.1.5.3',
    cipSecFailTable => '1.3.6.1.4.1.9.9.171.1.5.3.1',
    cipSecFailEntry => '1.3.6.1.4.1.9.9.171.1.5.3.1.1',
    cipSecFailIndex => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.1',
    cipSecFailReason => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.2',
    cipSecFailReasonDefinition => {
      '1' => 'other',
      '2' => 'internalError',
      '3' => 'peerEncodingError',
      '4' => 'proposalFailure',
      '5' => 'protocolUseFail',
      '6' => 'nonExistentSa',
      '7' => 'decryptFailure',
      '8' => 'encryptFailure',
      '9' => 'inAuthFailure',
      '10' => 'outAuthFailure',
      '11' => 'compression',
      '12' => 'sysCapExceeded',
      '13' => 'peerDelRequest',
      '14' => 'peerLost',
      '15' => 'seqNumRollOver',
      '16' => 'operRequest',
    },
    cipSecFailTime => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.3',
    cipSecFailTunnelIndex => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.4',
    cipSecFailSaSpi => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.5',
    cipSecFailPktSrcAddr => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.6',
    cipSecFailPktDstAddr => '1.3.6.1.4.1.9.9.171.1.5.3.1.1.7',
    cipSecTrapCntl => '1.3.6.1.4.1.9.9.171.1.6',
    cipSecTrapCntlIkeTunnelStart => '1.3.6.1.4.1.9.9.171.1.6.1',
    cipSecTrapCntlIkeTunnelStartDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIkeTunnelStop => '1.3.6.1.4.1.9.9.171.1.6.2',
    cipSecTrapCntlIkeTunnelStopDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIkeSysFailure => '1.3.6.1.4.1.9.9.171.1.6.3',
    cipSecTrapCntlIkeSysFailureDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIkeCertCrlFailure => '1.3.6.1.4.1.9.9.171.1.6.4',
    cipSecTrapCntlIkeCertCrlFailureDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIkeProtocolFail => '1.3.6.1.4.1.9.9.171.1.6.5',
    cipSecTrapCntlIkeProtocolFailDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIkeNoSa => '1.3.6.1.4.1.9.9.171.1.6.6',
    cipSecTrapCntlIkeNoSaDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecTunnelStart => '1.3.6.1.4.1.9.9.171.1.6.7',
    cipSecTrapCntlIpSecTunnelStartDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecTunnelStop => '1.3.6.1.4.1.9.9.171.1.6.8',
    cipSecTrapCntlIpSecTunnelStopDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecSysFailure => '1.3.6.1.4.1.9.9.171.1.6.9',
    cipSecTrapCntlIpSecSysFailureDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecSetUpFailure => '1.3.6.1.4.1.9.9.171.1.6.10',
    cipSecTrapCntlIpSecSetUpFailureDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecEarlyTunTerm => '1.3.6.1.4.1.9.9.171.1.6.11',
    cipSecTrapCntlIpSecEarlyTunTermDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecProtocolFail => '1.3.6.1.4.1.9.9.171.1.6.12',
    cipSecTrapCntlIpSecProtocolFailDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecTrapCntlIpSecNoSa => '1.3.6.1.4.1.9.9.171.1.6.13',
    cipSecTrapCntlIpSecNoSaDefinition => 'CISCO-IPSEC-FLOW-MONITOR-MIB::TrapStatus',
    cipSecMIBNotificationPrefix => '1.3.6.1.4.1.9.9.171.2',
    cipSecMIBNotifications => '1.3.6.1.4.1.9.9.171.2.0.1.2.3.4.5.6.7.8.9.10.11.12.13',
    cipSecMIBConformance => '1.3.6.1.4.1.9.9.171.3',
    cipSecMIBGroups => '1.3.6.1.4.1.9.9.171.3.1',
    cipSecMIBCompliances => '1.3.6.1.4.1.9.9.171.3.1.8',
    hardware => '1.3.6.1.4.1.3764.1.1.200',
  },
  'CISCO-ETHERNET-FABRIC-EXTENDER-MIB' => {
    enterprises => '1.3.6.1.4.1',
    cisco => '1.3.6.1.4.1.9',
    ciscoEthernetFabricExtenderMIB => '1.3.6.1.4.1.9.9.691',
    ciscoEthernetFabricExtenderMIBNotifs => '1.3.6.1.4.1.9.9.691.0',
    ciscoEthernetFabricExtenderObjects => '1.3.6.1.4.1.9.9.691.1',
    cefexConfig => '1.3.6.1.4.1.9.9.691.1.1',
    cefexConfigDefinition => {
      '1' => 'static',
    },
    cefexBindingTable => '1.3.6.1.4.1.9.9.691.1.1.1',
    cefexBindingEntry => '1.3.6.1.4.1.9.9.691.1.1.1.1',
    cefexBindingInterfaceOnCoreSwitch => '1.3.6.1.4.1.9.9.691.1.1.1.1.1',
    cefexBindingExtenderIndex => '1.3.6.1.4.1.9.9.691.1.1.1.1.2',
    cefexBindingCreationTime => '1.3.6.1.4.1.9.9.691.1.1.1.1.3',
    cefexBindingRowStatus => '1.3.6.1.4.1.9.9.691.1.1.1.1.4',
    cefexBindingRowStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    cefexConfigTable => '1.3.6.1.4.1.9.9.691.1.1.2',
    cefexConfigEntry => '1.3.6.1.4.1.9.9.691.1.1.2.1',
    cefexConfigExtenderName => '1.3.6.1.4.1.9.9.691.1.1.2.1.1',
    cefexConfigSerialNumCheck => '1.3.6.1.4.1.9.9.691.1.1.2.1.2',
    cefexConfigSerialNum => '1.3.6.1.4.1.9.9.691.1.1.2.1.3',
    cefexConfigPinningFailOverMode => '1.3.6.1.4.1.9.9.691.1.1.2.1.4',
    cefexConfigPinningFailOverModeDefinition => 'CISCO-ETHERNET-FABRIC-EXTENDER-MIB::CiscoPortPinningMode',
    cefexConfigPinningMaxLinks => '1.3.6.1.4.1.9.9.691.1.1.2.1.5',
    cefexConfigCreationTime => '1.3.6.1.4.1.9.9.691.1.1.2.1.6',
    cefexConfigRowStatus => '1.3.6.1.4.1.9.9.691.1.1.2.1.7',
    cefexConfigRowStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ciscoEthernetFabricExtenderMIBConformance => '1.3.6.1.4.1.9.9.691.2',
    cEthernetFabricExtenderMIBCompliances => '1.3.6.1.4.1.9.9.691.2.1',
    cEthernetFabricExtenderMIBGroups => '1.3.6.1.4.1.9.9.691.2.1.1.1',
    hardware => '1.3.6.1.4.1.3764.1.1.200',
  },
  'CISCO-BGP4-MIB' => {
      cbgpPeerAddrFamilyPrefixTable => '1.3.6.1.4.1.9.9.187.1.2.4',
      cbgpPeerAddrFamilyPrefixEntry => '1.3.6.1.4.1.9.9.187.1.2.4.1',
      cbgpPeerAddrAcceptedPrefixes => '1.3.6.1.4.1.9.9.187.1.2.4.1.1',
  },
  'AIRESPACE-SWITCHING-MIB' => {
      bsnSwitching => '1.3.6.1.4.1.14179.1',
      agentInfoGroup => '1.3.6.1.4.1.14179.1.1',
      agentInventoryGroup => '1.3.6.1.4.1.14179.1.1.1',
      agentInventorySysDescription => '1.3.6.1.4.1.14179.1.1.1.1',
      agentInventoryOperatingSystem => '1.3.6.1.4.1.14179.1.1.1.10',
      agentInventoryManufacturerName => '1.3.6.1.4.1.14179.1.1.1.12',
      agentInventoryProductName => '1.3.6.1.4.1.14179.1.1.1.13',
      agentInventoryProductVersion => '1.3.6.1.4.1.14179.1.1.1.14',
      agentInventoryIsGigECardPresent => '1.3.6.1.4.1.14179.1.1.1.15',
      agentInventoryIsCryptoCardPresent => '1.3.6.1.4.1.14179.1.1.1.16',
      agentInventoryIsForeignAPSupported => '1.3.6.1.4.1.14179.1.1.1.17',
      agentInventoryMaxNumberOfAPsSupported => '1.3.6.1.4.1.14179.1.1.1.18',
      agentInventoryIsCryptoCard2Present => '1.3.6.1.4.1.14179.1.1.1.19',
      agentInventoryMachineType => '1.3.6.1.4.1.14179.1.1.1.2',
      agentInventoryFipsModeEnabled => '1.3.6.1.4.1.14179.1.1.1.20',
      agentInventoryMachineModel => '1.3.6.1.4.1.14179.1.1.1.3',
      agentInventorySerialNumber => '1.3.6.1.4.1.14179.1.1.1.4',
      agentInventoryMaintenanceLevel => '1.3.6.1.4.1.14179.1.1.1.6',
      agentInventoryBurnedInMacAddress => '1.3.6.1.4.1.14179.1.1.1.9',
      agentTrapLogGroup => '1.3.6.1.4.1.14179.1.1.2',
      agentTrapLogTotal => '1.3.6.1.4.1.14179.1.1.2.1',
      agentApCoverageProfileFailTrapCount => '1.3.6.1.4.1.14179.1.1.2.10',
      agentTrapLogTotalSinceLastViewed => '1.3.6.1.4.1.14179.1.1.2.3',

      agentTrapLogTable => '1.3.6.1.4.1.14179.1.1.2.4',
      agentTrapLogEntry => '1.3.6.1.4.1.14179.1.1.2.4.1',
      agentTrapLogIndex => '1.3.6.1.4.1.14179.1.1.2.4.1.1',
      agentTrapLogSystemTime => '1.3.6.1.4.1.14179.1.1.2.4.1.2',
      agentTrapLogTrap => '1.3.6.1.4.1.14179.1.1.2.4.1.22',

      agentRadioUpDownTrapCount => '1.3.6.1.4.1.14179.1.1.2.5',
      agentApAssociateDisassociateTrapCount => '1.3.6.1.4.1.14179.1.1.2.6',
      agentApLoadProfileFailTrapCount => '1.3.6.1.4.1.14179.1.1.2.7',
      agentApNoiseProfileFailTrapCount => '1.3.6.1.4.1.14179.1.1.2.8',
      agentApInterferenceProfileFailTrapCount => '1.3.6.1.4.1.14179.1.1.2.9',
      agentSwitchInfoGroup => '1.3.6.1.4.1.14179.1.1.3',
      agentSwitchInfoLwappTransportMode => '1.3.6.1.4.1.14179.1.1.3.1',
      agentSwitchInfoPowerSupply1Present => '1.3.6.1.4.1.14179.1.1.3.2',
      agentSwitchInfoPowerSupply1PresentDefinition => {
          0 => 'false',
          1 => 'true',
      },
      agentSwitchInfoPowerSupply1Operational => '1.3.6.1.4.1.14179.1.1.3.3',
      agentSwitchInfoPowerSupply1OperationalDefinition => {
          0 => 'false',
          1 => 'true',
      },
      agentSwitchInfoPowerSupply2Present => '1.3.6.1.4.1.14179.1.1.3.4',
      agentSwitchInfoPowerSupply2PresentDefinition => {
          0 => 'false',
          1 => 'true',
      },
      agentSwitchInfoPowerSupply2Operational => '1.3.6.1.4.1.14179.1.1.3.5',
      agentSwitchInfoPowerSupply2OperationalDefinition => {
          0 => 'false',
          1 => 'true',
      },
      agentProductGroup => '1.3.6.1.4.1.14179.1.1.4',
      productGroup1 => '1.3.6.1.4.1.14179.1.1.4.1',
      productGroup2 => '1.3.6.1.4.1.14179.1.1.4.2',
      productGroup3 => '1.3.6.1.4.1.14179.1.1.4.3',
      productGroup4 => '1.3.6.1.4.1.14179.1.1.4.4',
      agentResourceInfoGroup => '1.3.6.1.4.1.14179.1.1.5',
      agentCurrentCPUUtilization => '1.3.6.1.4.1.14179.1.1.5.1.0',
      agentTotalMemory => '1.3.6.1.4.1.14179.1.1.5.2.0',
      agentFreeMemory => '1.3.6.1.4.1.14179.1.1.5.3.0',
      agentWcpInfoGroup => '1.3.6.1.4.1.14179.1.1.6',
      agentWcpDeviceName => '1.3.6.1.4.1.14179.1.1.6.1',
      agentWcpSlotNumber => '1.3.6.1.4.1.14179.1.1.6.2',
      agentWcpPortNumber => '1.3.6.1.4.1.14179.1.1.6.3',
      agentWcpPeerPortNumber => '1.3.6.1.4.1.14179.1.1.6.4',
      agentWcpPeerIpAddress => '1.3.6.1.4.1.14179.1.1.6.5',
      agentWcpControllerTableChecksum => '1.3.6.1.4.1.14179.1.1.6.6',

      agentWcpControllerInfoTable => '1.3.6.1.4.1.14179.1.1.6.7',
      agentWcpControllerInfoEntry => '1.3.6.1.4.1.14179.1.1.6.7.1',
      agentWcpControllerInfoSlotNumber => '1.3.6.1.4.1.14179.1.1.6.7.1.1',
      agentWcpControllerInfoIpAddress => '1.3.6.1.4.1.14179.1.1.6.7.1.10',
      agentWcpControllerInfoPortNumber => '1.3.6.1.4.1.14179.1.1.6.7.1.2',

      agentConfigGroup => '1.3.6.1.4.1.14179.1.2',
      agentCLIConfigGroup => '1.3.6.1.4.1.14179.1.2.1',

      agentLoginSessionTable => '1.3.6.1.4.1.14179.1.2.1.1',
      agentLoginSessionEntry => '1.3.6.1.4.1.14179.1.2.1.1.1',
      agentLoginSessionIndex => '1.3.6.1.4.1.14179.1.2.1.1.1.1',
      agentLoginSessionUserName => '1.3.6.1.4.1.14179.1.2.1.1.1.2',
      agentLoginSessionStatus => '1.3.6.1.4.1.14179.1.2.1.1.1.26',
      agentLoginSessionIPAddress => '1.3.6.1.4.1.14179.1.2.1.1.1.3',
      agentLoginSessionConnectionType => '1.3.6.1.4.1.14179.1.2.1.1.1.4',
      agentLoginSessionIdleTime => '1.3.6.1.4.1.14179.1.2.1.1.1.5',
      agentLoginSessionSessionTime => '1.3.6.1.4.1.14179.1.2.1.1.1.6',

      agentTelnetConfigGroup => '1.3.6.1.4.1.14179.1.2.1.2',
      agentTelnetLoginTimeout => '1.3.6.1.4.1.14179.1.2.1.2.1',
      agentTelnetMaxSessions => '1.3.6.1.4.1.14179.1.2.1.2.2',
      agentTelnetAllowNewMode => '1.3.6.1.4.1.14179.1.2.1.2.3',
      agentSSHAllowNewMode => '1.3.6.1.4.1.14179.1.2.1.2.4',
      agentSerialGroup => '1.3.6.1.4.1.14179.1.2.1.5',
      agentSerialTimeout => '1.3.6.1.4.1.14179.1.2.1.5.1',
      agentSerialBaudrate => '1.3.6.1.4.1.14179.1.2.1.5.2',
      agentSerialCharacterSize => '1.3.6.1.4.1.14179.1.2.1.5.3',
      agentSerialHWFlowControlMode => '1.3.6.1.4.1.14179.1.2.1.5.4',
      agentSerialStopBits => '1.3.6.1.4.1.14179.1.2.1.5.5',
      agentSerialParityType => '1.3.6.1.4.1.14179.1.2.1.5.6',
      agentDot3adAggPortTable => '1.3.6.1.4.1.14179.1.2.11',
      agentDot3adAggPortEntry => '1.3.6.1.4.1.14179.1.2.11.1',
      agentDot3adAggPort => '1.3.6.1.4.1.14179.1.2.11.1.1',
      agentDot3adAggPortLACPMode => '1.3.6.1.4.1.14179.1.2.11.1.21',
      agentPortConfigTable => '1.3.6.1.4.1.14179.1.2.12',
      agentPortConfigEntry => '1.3.6.1.4.1.14179.1.2.12.1',
      agentPortDot1dBasePort => '1.3.6.1.4.1.14179.1.2.12.1.1',
      agentPortClearStats => '1.3.6.1.4.1.14179.1.2.12.1.10',
      agentPortDefaultType => '1.3.6.1.4.1.14179.1.2.12.1.11',
      agentPortType => '1.3.6.1.4.1.14179.1.2.12.1.12',
      agentPortAutoNegAdminStatus => '1.3.6.1.4.1.14179.1.2.12.1.13',
      agentPortDot3FlowControlMode => '1.3.6.1.4.1.14179.1.2.12.1.14',
      agentPortPowerMode => '1.3.6.1.4.1.14179.1.2.12.1.15',
      agentPortGvrpStatus => '1.3.6.1.4.1.14179.1.2.12.1.16',
      agentPortGarpJoinTime => '1.3.6.1.4.1.14179.1.2.12.1.17',
      agentPortGarpLeaveTime => '1.3.6.1.4.1.14179.1.2.12.1.18',
      agentPortGarpLeaveAllTime => '1.3.6.1.4.1.14179.1.2.12.1.19',
      agentPortIfIndex => '1.3.6.1.4.1.14179.1.2.12.1.2',
      agentPortMirrorMode => '1.3.6.1.4.1.14179.1.2.12.1.20',
      agentPortMulticastApplianceMode => '1.3.6.1.4.1.14179.1.2.12.1.21',
      agentPortIanaType => '1.3.6.1.4.1.14179.1.2.12.1.3',
      agentPortSTPMode => '1.3.6.1.4.1.14179.1.2.12.1.4',
      agentPortOperationalStatus => '1.3.6.1.4.1.14179.1.2.12.1.40',
      agentPortSTPState => '1.3.6.1.4.1.14179.1.2.12.1.5',
      agentPortAdminMode => '1.3.6.1.4.1.14179.1.2.12.1.6',
      agentPortPhysicalMode => '1.3.6.1.4.1.14179.1.2.12.1.7',
      agentPortPhysicalStatus => '1.3.6.1.4.1.14179.1.2.12.1.8',
      agentPortLinkTrapMode => '1.3.6.1.4.1.14179.1.2.12.1.9',
      agentInterfaceConfigTable => '1.3.6.1.4.1.14179.1.2.13',
      agentInterfaceConfigEntry => '1.3.6.1.4.1.14179.1.2.13.1',
      agentInterfaceName => '1.3.6.1.4.1.14179.1.2.13.1.1',
      agentInterfaceSecondaryDhcpAddress => '1.3.6.1.4.1.14179.1.2.13.1.10',
      agentInterfaceDhcpProtocol => '1.3.6.1.4.1.14179.1.2.13.1.11',
      agentInterfaceDnsHostName => '1.3.6.1.4.1.14179.1.2.13.1.12',
      agentInterfaceAclName => '1.3.6.1.4.1.14179.1.2.13.1.13',
      agentInterfaceAPManagementFeature => '1.3.6.1.4.1.14179.1.2.13.1.14',
      agentInterfaceActivePortNo => '1.3.6.1.4.1.14179.1.2.13.1.15',
      agentInterfaceBackupPortNo => '1.3.6.1.4.1.14179.1.2.13.1.16',
      agentInterfaceVlanQuarantine => '1.3.6.1.4.1.14179.1.2.13.1.17',
      agentInterfaceVlanId => '1.3.6.1.4.1.14179.1.2.13.1.2',
      agentInterfaceType => '1.3.6.1.4.1.14179.1.2.13.1.3',
      agentInterfaceRowStatus => '1.3.6.1.4.1.14179.1.2.13.1.31',
      agentInterfaceMacAddress => '1.3.6.1.4.1.14179.1.2.13.1.4',
      agentInterfaceIPAddress => '1.3.6.1.4.1.14179.1.2.13.1.5',
      agentInterfaceIPNetmask => '1.3.6.1.4.1.14179.1.2.13.1.6',
      agentInterfaceIPGateway => '1.3.6.1.4.1.14179.1.2.13.1.7',
      agentInterfacePortNo => '1.3.6.1.4.1.14179.1.2.13.1.8',
      agentInterfacePrimaryDhcpAddress => '1.3.6.1.4.1.14179.1.2.13.1.9',
      agentNtpConfigGroup => '1.3.6.1.4.1.14179.1.2.14',
      agentNtpPollingInterval => '1.3.6.1.4.1.14179.1.2.14.1',
      agentNtpServerTable => '1.3.6.1.4.1.14179.1.2.14.2',
      agentNtpServerEntry => '1.3.6.1.4.1.14179.1.2.14.2.1',
      agentNtpServerIndex => '1.3.6.1.4.1.14179.1.2.14.2.1.1',
      agentNtpServerAddress => '1.3.6.1.4.1.14179.1.2.14.2.1.2',
      agentNtpServerRowStatus => '1.3.6.1.4.1.14179.1.2.14.2.1.20',
      agentDhcpConfigGroup => '1.3.6.1.4.1.14179.1.2.15',
      agentDhcpScopeTable => '1.3.6.1.4.1.14179.1.2.15.1',
      agentDhcpScopeEntry => '1.3.6.1.4.1.14179.1.2.15.1.1',
      agentDhcpScopeIndex => '1.3.6.1.4.1.14179.1.2.15.1.1.1',
      agentDhcpScopeDefaultRouterAddress3 => '1.3.6.1.4.1.14179.1.2.15.1.1.10',
      agentDhcpScopeDnsDomainName => '1.3.6.1.4.1.14179.1.2.15.1.1.11',
      agentDhcpScopeDnsServerAddress1 => '1.3.6.1.4.1.14179.1.2.15.1.1.12',
      agentDhcpScopeDnsServerAddress2 => '1.3.6.1.4.1.14179.1.2.15.1.1.13',
      agentDhcpScopeDnsServerAddress3 => '1.3.6.1.4.1.14179.1.2.15.1.1.14',
      agentDhcpScopeNetbiosNameServerAddress1 => '1.3.6.1.4.1.14179.1.2.15.1.1.15',
      agentDhcpScopeNetbiosNameServerAddress2 => '1.3.6.1.4.1.14179.1.2.15.1.1.16',
      agentDhcpScopeNetbiosNameServerAddress3 => '1.3.6.1.4.1.14179.1.2.15.1.1.17',
      agentDhcpScopeState => '1.3.6.1.4.1.14179.1.2.15.1.1.18',
      agentDhcpScopeName => '1.3.6.1.4.1.14179.1.2.15.1.1.2',
      agentDhcpScopeLeaseTime => '1.3.6.1.4.1.14179.1.2.15.1.1.3',
      agentDhcpScopeRowStatus => '1.3.6.1.4.1.14179.1.2.15.1.1.30',
      agentDhcpScopeNetwork => '1.3.6.1.4.1.14179.1.2.15.1.1.4',
      agentDhcpScopeNetmask => '1.3.6.1.4.1.14179.1.2.15.1.1.5',
      agentDhcpScopePoolStartAddress => '1.3.6.1.4.1.14179.1.2.15.1.1.6',
      agentDhcpScopePoolEndAddress => '1.3.6.1.4.1.14179.1.2.15.1.1.7',
      agentDhcpScopeDefaultRouterAddress1 => '1.3.6.1.4.1.14179.1.2.15.1.1.8',
      agentDhcpScopeDefaultRouterAddress2 => '1.3.6.1.4.1.14179.1.2.15.1.1.9',
      agentLagConfigGroup => '1.3.6.1.4.1.14179.1.2.2',
      agentLagConfigCreate => '1.3.6.1.4.1.14179.1.2.2.1',
      agentLagSummaryConfigTable => '1.3.6.1.4.1.14179.1.2.2.2',
      agentLagSummaryConfigEntry => '1.3.6.1.4.1.14179.1.2.2.2.1',
      agentLagSummaryName => '1.3.6.1.4.1.14179.1.2.2.2.1.1',
      agentLagSummaryLagIndex => '1.3.6.1.4.1.14179.1.2.2.2.1.2',
      agentLagSummaryFlushTimer => '1.3.6.1.4.1.14179.1.2.2.2.1.3',
      agentLagSummaryStatus => '1.3.6.1.4.1.14179.1.2.2.2.1.30',
      agentLagSummaryLinkTrap => '1.3.6.1.4.1.14179.1.2.2.2.1.4',
      agentLagSummaryAdminMode => '1.3.6.1.4.1.14179.1.2.2.2.1.5',
      agentLagSummaryStpMode => '1.3.6.1.4.1.14179.1.2.2.2.1.6',
      agentLagSummaryAddPort => '1.3.6.1.4.1.14179.1.2.2.2.1.7',
      agentLagSummaryDeletePort => '1.3.6.1.4.1.14179.1.2.2.2.1.8',
      agentLagSummaryPortsBitMask => '1.3.6.1.4.1.14179.1.2.2.2.1.9',
      agentLagDetailedConfigTable => '1.3.6.1.4.1.14179.1.2.2.3',
      agentLagDetailedConfigEntry => '1.3.6.1.4.1.14179.1.2.2.3.1',
      agentLagDetailedLagIndex => '1.3.6.1.4.1.14179.1.2.2.3.1.1',
      agentLagDetailedIfIndex => '1.3.6.1.4.1.14179.1.2.2.3.1.2',
      agentLagDetailedPortSpeed => '1.3.6.1.4.1.14179.1.2.2.3.1.22',
      agentLagConfigMode => '1.3.6.1.4.1.14179.1.2.2.4',
      agentNetworkConfigGroup => '1.3.6.1.4.1.14179.1.2.3',
      agentNetworkIPAddress => '1.3.6.1.4.1.14179.1.2.3.1',
      agentNetworkMulticastMode => '1.3.6.1.4.1.14179.1.2.3.10',
      agentNetworkDsPortNumber => '1.3.6.1.4.1.14179.1.2.3.11',
      agentNetworkUserIdleTimeout => '1.3.6.1.4.1.14179.1.2.3.12',
      agentNetworkArpTimeout => '1.3.6.1.4.1.14179.1.2.3.13',
      agentNetworkManagementVlan => '1.3.6.1.4.1.14179.1.2.3.14',
      agentNetworkGvrpStatus => '1.3.6.1.4.1.14179.1.2.3.15',
      agentNetworkAllowMgmtViaWireless => '1.3.6.1.4.1.14179.1.2.3.16',
      agentNetworkBroadcastSsidMode => '1.3.6.1.4.1.14179.1.2.3.17',
      agentNetworkSecureWebPassword => '1.3.6.1.4.1.14179.1.2.3.18',
      agentNetworkWebAdminCertType => '1.3.6.1.4.1.14179.1.2.3.19',
      agentNetworkSubnetMask => '1.3.6.1.4.1.14179.1.2.3.2',
      agentNetworkWebAdminCertRegenerateCmdInvoke => '1.3.6.1.4.1.14179.1.2.3.20',
      agentNetworkWebAuthCertType => '1.3.6.1.4.1.14179.1.2.3.21',
      agentNetworkWebAuthCertRegenerateCmdInvoke => '1.3.6.1.4.1.14179.1.2.3.22',
      agentNetworkRouteConfigTable => '1.3.6.1.4.1.14179.1.2.3.23',
      agentNetworkRouteConfigEntry => '1.3.6.1.4.1.14179.1.2.3.23.1',
      agentNetworkRouteIPAddress => '1.3.6.1.4.1.14179.1.2.3.23.1.1',
      agentNetworkRouteIPNetmask => '1.3.6.1.4.1.14179.1.2.3.23.1.2',
      agentNetworkRouteStatus => '1.3.6.1.4.1.14179.1.2.3.23.1.23',
      agentNetworkRouteGateway => '1.3.6.1.4.1.14179.1.2.3.23.1.3',
      agentNetworkPeerToPeerBlockingMode => '1.3.6.1.4.1.14179.1.2.3.24',
      agentNetworkMulticastGroupAddress => '1.3.6.1.4.1.14179.1.2.3.25',
      agentNetworkDefaultGateway => '1.3.6.1.4.1.14179.1.2.3.3',
      agentNetworkBurnedInMacAddress => '1.3.6.1.4.1.14179.1.2.3.4',
      agentNetworkConfigProtocol => '1.3.6.1.4.1.14179.1.2.3.7',
      agentNetworkWebMode => '1.3.6.1.4.1.14179.1.2.3.8',
      agentNetworkSecureWebMode => '1.3.6.1.4.1.14179.1.2.3.9',
      agentServicePortConfigGroup => '1.3.6.1.4.1.14179.1.2.4',
      agentServicePortIPAddress => '1.3.6.1.4.1.14179.1.2.4.1',
      agentServicePortSubnetMask => '1.3.6.1.4.1.14179.1.2.4.2',
      agentServicePortDefaultGateway => '1.3.6.1.4.1.14179.1.2.4.3',
      agentServicePortBurnedInMacAddress => '1.3.6.1.4.1.14179.1.2.4.4',
      agentServicePortConfigProtocol => '1.3.6.1.4.1.14179.1.2.4.5',
      agentSnmpConfigGroup => '1.3.6.1.4.1.14179.1.2.5',
      agentSnmpTrapPortNumber => '1.3.6.1.4.1.14179.1.2.5.1',
      agentSnmpVersion1Status => '1.3.6.1.4.1.14179.1.2.5.2',
      agentSnmpVersion2cStatus => '1.3.6.1.4.1.14179.1.2.5.3',
      agentSnmpCommunityConfigTable => '1.3.6.1.4.1.14179.1.2.5.5',
      agentSnmpCommunityConfigEntry => '1.3.6.1.4.1.14179.1.2.5.5.1',
      agentSnmpCommunityName => '1.3.6.1.4.1.14179.1.2.5.5.1.1',
      agentSnmpCommunityIPAddress => '1.3.6.1.4.1.14179.1.2.5.5.1.2',
      agentSnmpCommunityStatus => '1.3.6.1.4.1.14179.1.2.5.5.1.25',
      agentSnmpCommunityIPMask => '1.3.6.1.4.1.14179.1.2.5.5.1.3',
      agentSnmpCommunityAccessMode => '1.3.6.1.4.1.14179.1.2.5.5.1.4',
      agentSnmpCommunityEnabled => '1.3.6.1.4.1.14179.1.2.5.5.1.5',
      agentSnmpTrapReceiverConfigTable => '1.3.6.1.4.1.14179.1.2.5.6',
      agentSnmpTrapReceiverConfigEntry => '1.3.6.1.4.1.14179.1.2.5.6.1',
      agentSnmpTrapReceiverName => '1.3.6.1.4.1.14179.1.2.5.6.1.1',
      agentSnmpTrapReceiverIPAddress => '1.3.6.1.4.1.14179.1.2.5.6.1.2',
      agentSnmpTrapReceiverStatus => '1.3.6.1.4.1.14179.1.2.5.6.1.23',
      agentSnmpTrapReceiverEnabled => '1.3.6.1.4.1.14179.1.2.5.6.1.3',
      agentSnmpTrapFlagsConfigGroup => '1.3.6.1.4.1.14179.1.2.5.7',
      agentSnmpAuthenticationTrapFlag => '1.3.6.1.4.1.14179.1.2.5.7.1',
      agentSnmpLinkUpDownTrapFlag => '1.3.6.1.4.1.14179.1.2.5.7.2',
      agentSnmpMultipleUsersTrapFlag => '1.3.6.1.4.1.14179.1.2.5.7.3',
      agentSnmpSpanningTreeTrapFlag => '1.3.6.1.4.1.14179.1.2.5.7.4',
      agentSnmpBroadcastStormTrapFlag => '1.3.6.1.4.1.14179.1.2.5.7.5',
      agentSnmpV3ConfigGroup => '1.3.6.1.4.1.14179.1.2.6',
      agentSnmpVersion3Status => '1.3.6.1.4.1.14179.1.2.6.1',
      agentSnmpV3UserConfigTable => '1.3.6.1.4.1.14179.1.2.6.2',
      agentSnmpV3UserConfigEntry => '1.3.6.1.4.1.14179.1.2.6.2.1',
      agentSnmpV3UserName => '1.3.6.1.4.1.14179.1.2.6.2.1.1',
      agentSnmpV3UserAccessMode => '1.3.6.1.4.1.14179.1.2.6.2.1.2',
      agentSnmpV3UserStatus => '1.3.6.1.4.1.14179.1.2.6.2.1.26',
      agentSnmpV3UserAuthenticationType => '1.3.6.1.4.1.14179.1.2.6.2.1.3',
      agentSnmpV3UserEncryptionType => '1.3.6.1.4.1.14179.1.2.6.2.1.4',
      agentSnmpV3UserAuthenticationPassword => '1.3.6.1.4.1.14179.1.2.6.2.1.5',
      agentSnmpV3UserEncryptionPassword => '1.3.6.1.4.1.14179.1.2.6.2.1.6',
      agentSpanningTreeConfigGroup => '1.3.6.1.4.1.14179.1.2.7',
      agentSpanningTreeMode => '1.3.6.1.4.1.14179.1.2.7.1',
      agentSwitchConfigGroup => '1.3.6.1.4.1.14179.1.2.8',
      agentSwitchBroadcastControlMode => '1.3.6.1.4.1.14179.1.2.8.2',
      agentSwitchDot3FlowControlMode => '1.3.6.1.4.1.14179.1.2.8.3',
      agentSwitchAddressAgingTimeoutTable => '1.3.6.1.4.1.14179.1.2.8.4',
      agentSwitchAddressAgingTimeoutEntry => '1.3.6.1.4.1.14179.1.2.8.4.1',
      agentSwitchAddressAgingTimeout => '1.3.6.1.4.1.14179.1.2.8.4.1.10',
      agentSwitchLwappTransportMode => '1.3.6.1.4.1.14179.1.2.8.5',
      agentTransferConfigGroup => '1.3.6.1.4.1.14179.1.2.9',
      agentTransferUploadGroup => '1.3.6.1.4.1.14179.1.2.9.1',
      agentTransferUploadMode => '1.3.6.1.4.1.14179.1.2.9.1.1',
      agentTransferUploadServerIP => '1.3.6.1.4.1.14179.1.2.9.1.2',
      agentTransferUploadPath => '1.3.6.1.4.1.14179.1.2.9.1.3',
      agentTransferUploadFilename => '1.3.6.1.4.1.14179.1.2.9.1.4',
      agentTransferUploadDataType => '1.3.6.1.4.1.14179.1.2.9.1.5',
      agentTransferUploadStart => '1.3.6.1.4.1.14179.1.2.9.1.6',
      agentTransferUploadStatus => '1.3.6.1.4.1.14179.1.2.9.1.7',
      agentTransferDownloadGroup => '1.3.6.1.4.1.14179.1.2.9.2',
      agentTransferDownloadMode => '1.3.6.1.4.1.14179.1.2.9.2.1',
      agentTransferDownloadServerIP => '1.3.6.1.4.1.14179.1.2.9.2.2',
      agentTransferDownloadPath => '1.3.6.1.4.1.14179.1.2.9.2.3',
      agentTransferDownloadFilename => '1.3.6.1.4.1.14179.1.2.9.2.4',
      agentTransferDownloadDataType => '1.3.6.1.4.1.14179.1.2.9.2.5',
      agentTransferDownloadStart => '1.3.6.1.4.1.14179.1.2.9.2.6',
      agentTransferDownloadStatus => '1.3.6.1.4.1.14179.1.2.9.2.7',
      agentTransferDownloadTftpMaxRetries => '1.3.6.1.4.1.14179.1.2.9.2.8',
      agentTransferDownloadTftpTimeout => '1.3.6.1.4.1.14179.1.2.9.2.9',
      agentTransferConfigurationFileEncryption => '1.3.6.1.4.1.14179.1.2.9.3',
      agentTransferConfigurationFileEncryptionKey => '1.3.6.1.4.1.14179.1.2.9.4',
      agentSystemGroup => '1.3.6.1.4.1.14179.1.3',
      agentSaveConfig => '1.3.6.1.4.1.14179.1.3.1',
      agentResetSystem => '1.3.6.1.4.1.14179.1.3.10',
      agentClearConfig => '1.3.6.1.4.1.14179.1.3.2',
      agentClearLags => '1.3.6.1.4.1.14179.1.3.3',
      agentClearLoginSessions => '1.3.6.1.4.1.14179.1.3.4',
      agentClearPortStats => '1.3.6.1.4.1.14179.1.3.6',
      agentClearSwitchStats => '1.3.6.1.4.1.14179.1.3.7',
      agentClearTrapLog => '1.3.6.1.4.1.14179.1.3.8',
      stats => '1.3.6.1.4.1.14179.1.4',
      portStatsTable => '1.3.6.1.4.1.14179.1.4.1',
      portStatsEntry => '1.3.6.1.4.1.14179.1.4.1.1',
      portStatsIndex => '1.3.6.1.4.1.14179.1.4.1.1.1',
      portStatsPktsTx64Octets => '1.3.6.1.4.1.14179.1.4.1.1.2',
      portStatsPktsTx65to127Octets => '1.3.6.1.4.1.14179.1.4.1.1.3',
      portStatsPktsTxOversizeOctets => '1.3.6.1.4.1.14179.1.4.1.1.30',
      portStatsPktsTx128to255Octets => '1.3.6.1.4.1.14179.1.4.1.1.4',
      portStatsPktsTx256to511Octets => '1.3.6.1.4.1.14179.1.4.1.1.5',
      portStatsPktsTx512to1023Octets => '1.3.6.1.4.1.14179.1.4.1.1.6',
      portStatsPktsTx1024to1518Octets => '1.3.6.1.4.1.14179.1.4.1.1.7',
      portStatsPktsRx1519to1530Octets => '1.3.6.1.4.1.14179.1.4.1.1.8',
      portStatsPktsTx1519to1530Octets => '1.3.6.1.4.1.14179.1.4.1.1.9',
      switchingTraps => '1.3.6.1.4.1.14179.1.50',
      multipleUsersTrap => '1.3.6.1.4.1.14179.1.50.1',
      stpInstanceNewRootTrap => '1.3.6.1.4.1.14179.1.50.10',
      stpInstanceTopologyChangeTrap => '1.3.6.1.4.1.14179.1.50.11',
      powerSupplyStatusChangeTrap => '1.3.6.1.4.1.14179.1.50.12',
      broadcastStormStartTrap => '1.3.6.1.4.1.14179.1.50.2',
      broadcastStormEndTrap => '1.3.6.1.4.1.14179.1.50.3',
      linkFailureTrap => '1.3.6.1.4.1.14179.1.50.4',
      vlanRequestFailureTrap => '1.3.6.1.4.1.14179.1.50.5',
      vlanDeleteLastTrap => '1.3.6.1.4.1.14179.1.50.6',
      vlanDefaultCfgFailureTrap => '1.3.6.1.4.1.14179.1.50.7',
      vlanRestoreFailureTrap => '1.3.6.1.4.1.14179.1.50.8',
      fanFailureTrap => '1.3.6.1.4.1.14179.1.50.9',
      bsnSwitchingGroups => '1.3.6.1.4.1.14179.1.51',
      bsnSwitchingAgentInfoGroup => '1.3.6.1.4.1.14179.1.51.1',
      bsnSwitchingAgentConfigGroup => '1.3.6.1.4.1.14179.1.51.2',
      bsnSwitchingAgentSystemGroup => '1.3.6.1.4.1.14179.1.51.3',
      bsnSwitchingAgentStatsGroup => '1.3.6.1.4.1.14179.1.51.4',
      bsnSwitchingObsGroup => '1.3.6.1.4.1.14179.1.51.5',
      bsnSwitchingTrap => '1.3.6.1.4.1.14179.1.51.6',
      bsnSwitchingCompliances => '1.3.6.1.4.1.14179.1.52',
      bsnSwitchingCompliance => '1.3.6.1.4.1.14179.1.52.1',
  },
  'AIRESPACE-WIRELESS-MIB' => {
      bsnWireless => '1.3.6.1.4.1.14179.2',
      bsnEss => '1.3.6.1.4.1.14179.2.1',
      bsnDot11EssTable => '1.3.6.1.4.1.14179.2.1.1',
      bsnDot11EssEntry => '1.3.6.1.4.1.14179.2.1.1.1',
      bsnDot11EssIndex => '1.3.6.1.4.1.14179.2.1.1.1.1',
      bsnDot11EssStaticWEPDefaultKey => '1.3.6.1.4.1.14179.2.1.1.1.10',
      bsnDot11EssRadiusAcctTertiaryServer => '1.3.6.1.4.1.14179.2.1.1.1.100',
      bsnDot11EssStaticWEPKeyIndex => '1.3.6.1.4.1.14179.2.1.1.1.11',
      bsnDot11EssStaticWEPKeyFormat => '1.3.6.1.4.1.14179.2.1.1.1.12',
      bsnDot11Ess8021xSecurity => '1.3.6.1.4.1.14179.2.1.1.1.13',
      bsnDot11Ess8021xEncryptionType => '1.3.6.1.4.1.14179.2.1.1.1.14',
      bsnDot11EssWPASecurity => '1.3.6.1.4.1.14179.2.1.1.1.16',
      bsnDot11EssWPAEncryptionType => '1.3.6.1.4.1.14179.2.1.1.1.17',
      bsnDot11EssIpsecSecurity => '1.3.6.1.4.1.14179.2.1.1.1.18',
      bsnDot11EssVpnEncrTransform => '1.3.6.1.4.1.14179.2.1.1.1.19',
      bsnDot11EssSsid => '1.3.6.1.4.1.14179.2.1.1.1.2',
      bsnDot11EssVpnAuthTransform => '1.3.6.1.4.1.14179.2.1.1.1.20',
      bsnDot11EssVpnIkeAuthMode => '1.3.6.1.4.1.14179.2.1.1.1.21',
      bsnDot11EssVpnSharedKey => '1.3.6.1.4.1.14179.2.1.1.1.22',
      bsnDot11EssVpnSharedKeySize => '1.3.6.1.4.1.14179.2.1.1.1.23',
      bsnDot11EssVpnIkePhase1Mode => '1.3.6.1.4.1.14179.2.1.1.1.24',
      bsnDot11EssVpnIkeLifetime => '1.3.6.1.4.1.14179.2.1.1.1.25',
      bsnDot11EssVpnIkeDHGroup => '1.3.6.1.4.1.14179.2.1.1.1.26',
      bsnDot11EssIpsecPassthruSecurity => '1.3.6.1.4.1.14179.2.1.1.1.27',
      bsnDot11EssVpnPassthruGateway => '1.3.6.1.4.1.14179.2.1.1.1.28',
      bsnDot11EssWebSecurity => '1.3.6.1.4.1.14179.2.1.1.1.29',
      bsnDot11EssRadioPolicy => '1.3.6.1.4.1.14179.2.1.1.1.30',
      bsnDot11EssQualityOfService => '1.3.6.1.4.1.14179.2.1.1.1.31',
      bsnDot11EssDhcpRequired => '1.3.6.1.4.1.14179.2.1.1.1.32',
      bsnDot11EssDhcpServerIpAddress => '1.3.6.1.4.1.14179.2.1.1.1.33',
      bsnDot11EssVpnContivityMode => '1.3.6.1.4.1.14179.2.1.1.1.34',
      bsnDot11EssVpnQotdServerAddress => '1.3.6.1.4.1.14179.2.1.1.1.35',
      bsnDot11EssBlacklistTimeout => '1.3.6.1.4.1.14179.2.1.1.1.37',
      bsnDot11EssNumberOfMobileStations => '1.3.6.1.4.1.14179.2.1.1.1.38',
      bsnDot11EssWebPassthru => '1.3.6.1.4.1.14179.2.1.1.1.39',
      bsnDot11EssSessionTimeout => '1.3.6.1.4.1.14179.2.1.1.1.4',
      bsnDot11EssCraniteSecurity => '1.3.6.1.4.1.14179.2.1.1.1.40',
      bsnDot11EssBlacklistingCapability => '1.3.6.1.4.1.14179.2.1.1.1.41',
      bsnDot11EssInterfaceName => '1.3.6.1.4.1.14179.2.1.1.1.42',
      bsnDot11EssAclName => '1.3.6.1.4.1.14179.2.1.1.1.43',
      bsnDot11EssAAAOverride => '1.3.6.1.4.1.14179.2.1.1.1.44',
      bsnDot11EssWPAAuthKeyMgmtMode => '1.3.6.1.4.1.14179.2.1.1.1.45',
      bsnDot11EssWPAAuthPresharedKey => '1.3.6.1.4.1.14179.2.1.1.1.46',
      bsnDot11EssFortressSecurity => '1.3.6.1.4.1.14179.2.1.1.1.47',
      bsnDot11EssWepAllowSharedKeyAuth => '1.3.6.1.4.1.14179.2.1.1.1.48',
      bsnDot11EssL2tpSecurity => '1.3.6.1.4.1.14179.2.1.1.1.49',
      bsnDot11EssMacFiltering => '1.3.6.1.4.1.14179.2.1.1.1.5',
      bsnDot11EssWPAAuthPresharedKeyHex => '1.3.6.1.4.1.14179.2.1.1.1.50',
      bsnDot11EssBroadcastSsid => '1.3.6.1.4.1.14179.2.1.1.1.51',
      bsnDot11EssExternalPolicyValidation => '1.3.6.1.4.1.14179.2.1.1.1.52',
      bsnDot11EssRSNSecurity => '1.3.6.1.4.1.14179.2.1.1.1.53',
      bsnDot11EssRSNWPACompatibilityMode => '1.3.6.1.4.1.14179.2.1.1.1.54',
      bsnDot11EssRSNAllowTKIPClients => '1.3.6.1.4.1.14179.2.1.1.1.55',
      bsnDot11EssRSNAuthKeyMgmtMode => '1.3.6.1.4.1.14179.2.1.1.1.56',
      bsnDot11EssRSNAuthPresharedKey => '1.3.6.1.4.1.14179.2.1.1.1.57',
      bsnDot11EssRSNAuthPresharedKeyHex => '1.3.6.1.4.1.14179.2.1.1.1.58',
      bsnDot11EssIPv6Bridging => '1.3.6.1.4.1.14179.2.1.1.1.59',
      bsnDot11EssAdminStatus => '1.3.6.1.4.1.14179.2.1.1.1.6',
      bsnDot11EssRowStatus => '1.3.6.1.4.1.14179.2.1.1.1.60',
      bsnDot11EssWmePolicySetting => '1.3.6.1.4.1.14179.2.1.1.1.61',
      bsnDot11Ess80211ePolicySetting => '1.3.6.1.4.1.14179.2.1.1.1.62',
      bsnDot11EssWebPassthroughEmail => '1.3.6.1.4.1.14179.2.1.1.1.63',
      bsnDot11Ess7920PhoneSupport => '1.3.6.1.4.1.14179.2.1.1.1.64',
      bsnDot11EssSecurityAuthType => '1.3.6.1.4.1.14179.2.1.1.1.7',
      bsnDot11EssStaticWEPSecurity => '1.3.6.1.4.1.14179.2.1.1.1.8',
      bsnDot11EssStaticWEPEncryptionType => '1.3.6.1.4.1.14179.2.1.1.1.9',
      bsnDot11EssRadiusAuthPrimaryServer => '1.3.6.1.4.1.14179.2.1.1.1.95',
      bsnDot11EssRadiusAuthSecondaryServer => '1.3.6.1.4.1.14179.2.1.1.1.96',
      bsnDot11EssRadiusAuthTertiaryServer => '1.3.6.1.4.1.14179.2.1.1.1.97',
      bsnDot11EssRadiusAcctPrimaryServer => '1.3.6.1.4.1.14179.2.1.1.1.98',
      bsnDot11EssRadiusAcctSecondaryServer => '1.3.6.1.4.1.14179.2.1.1.1.99',
      bsnMobileStationByIpTable => '1.3.6.1.4.1.14179.2.1.10',
      bsnMobileStationByIpEntry => '1.3.6.1.4.1.14179.2.1.10.1',
      bsnMobileStationByIpAddress => '1.3.6.1.4.1.14179.2.1.10.1.1',
      bsnMobileStationByIpMacAddress => '1.3.6.1.4.1.14179.2.1.10.1.2',
      bsnMobileStationRssiDataTable => '1.3.6.1.4.1.14179.2.1.11',
      bsnMobileStationRssiDataEntry => '1.3.6.1.4.1.14179.2.1.11.1',
      bsnMobileStationRssiDataApMacAddress => '1.3.6.1.4.1.14179.2.1.11.1.1',
      bsnMobileStationRssiDataApIfSlotId => '1.3.6.1.4.1.14179.2.1.11.1.2',
      bsnMobileStationRssiDataLastHeard => '1.3.6.1.4.1.14179.2.1.11.1.25',
      bsnMobileStationRssiDataApIfType => '1.3.6.1.4.1.14179.2.1.11.1.3',
      bsnMobileStationRssiDataApName => '1.3.6.1.4.1.14179.2.1.11.1.4',
      bsnMobileStationRssiData => '1.3.6.1.4.1.14179.2.1.11.1.5',
      bsnAPIfPhyAntennaIndex => '1.3.6.1.4.1.14179.2.1.11.1.6',
      bsnWatchListClientTable => '1.3.6.1.4.1.14179.2.1.12',
      bsnWatchListClientEntry => '1.3.6.1.4.1.14179.2.1.12.1',
      bsnWatchListClientKey => '1.3.6.1.4.1.14179.2.1.12.1.1',
      bsnWatchListClientType => '1.3.6.1.4.1.14179.2.1.12.1.2',
      bsnWatchListClientRowStatus => '1.3.6.1.4.1.14179.2.1.12.1.20',
      bsnMobileStationByUsernameTable => '1.3.6.1.4.1.14179.2.1.13',
      bsnMobileStationByUsernameEntry => '1.3.6.1.4.1.14179.2.1.13.1',
      bsnMobileStationByUserName => '1.3.6.1.4.1.14179.2.1.13.1.1',
      bsnMobileStationByUserMacAddress => '1.3.6.1.4.1.14179.2.1.13.1.2',
      bsnRogueClientTable => '1.3.6.1.4.1.14179.2.1.14',
      bsnRogueClientEntry => '1.3.6.1.4.1.14179.2.1.14.1',
      bsnRogueClientDot11MacAddress => '1.3.6.1.4.1.14179.2.1.14.1.1',
      bsnRogueClientTotalDetectingAPs => '1.3.6.1.4.1.14179.2.1.14.1.2',
      bsnRogueClientState => '1.3.6.1.4.1.14179.2.1.14.1.24',
      bsnRogueClientFirstReported => '1.3.6.1.4.1.14179.2.1.14.1.3',
      bsnRogueClientLastReported => '1.3.6.1.4.1.14179.2.1.14.1.4',
      bsnRogueClientBSSID => '1.3.6.1.4.1.14179.2.1.14.1.5',
      bsnRogueClientContainmentLevel => '1.3.6.1.4.1.14179.2.1.14.1.6',
      bsnRogueClientLastHeard => '1.3.6.1.4.1.14179.2.1.14.1.7',
      bsnRogueClientAirespaceAPTable => '1.3.6.1.4.1.14179.2.1.15',
      bsnRogueClientAirespaceAPEntry => '1.3.6.1.4.1.14179.2.1.15.1',
      bsnRogueClientAirespaceAPMacAddress => '1.3.6.1.4.1.14179.2.1.15.1.1',
      bsnRogueClientAirespaceAPLastHeard => '1.3.6.1.4.1.14179.2.1.15.1.11',
      bsnRogueClientAirespaceAPSlotId => '1.3.6.1.4.1.14179.2.1.15.1.2',
      bsnRogueClientAirespaceAPSNR => '1.3.6.1.4.1.14179.2.1.15.1.27',
      bsnRogueClientRadioType => '1.3.6.1.4.1.14179.2.1.15.1.3',
      bsnRogueClientAirespaceAPName => '1.3.6.1.4.1.14179.2.1.15.1.4',
      bsnRogueClientChannelNumber => '1.3.6.1.4.1.14179.2.1.15.1.5',
      bsnRogueClientAirespaceAPRSSI => '1.3.6.1.4.1.14179.2.1.15.1.7',
      bsnRogueClientPerRogueAPTable => '1.3.6.1.4.1.14179.2.1.16',
      bsnRogueClientPerRogueAPEntry => '1.3.6.1.4.1.14179.2.1.16.1',
      bsnRogueAPDot11MacAddr => '1.3.6.1.4.1.14179.2.1.16.1.1',
      bsnRogueClientDot11MacAddr => '1.3.6.1.4.1.14179.2.1.16.1.20',
      bsnDot11QosProfileTable => '1.3.6.1.4.1.14179.2.1.17',
      bsnDot11QosProfileEntry => '1.3.6.1.4.1.14179.2.1.17.1',
      bsnDot11QosProfileName => '1.3.6.1.4.1.14179.2.1.17.1.1',
      bsnDot11802Dot1PTag => '1.3.6.1.4.1.14179.2.1.17.1.10',
      bsnDot11QosProfileDesc => '1.3.6.1.4.1.14179.2.1.17.1.2',
      bsnDot11QosAverageDataRate => '1.3.6.1.4.1.14179.2.1.17.1.3',
      bsnDot11QosBurstDataRate => '1.3.6.1.4.1.14179.2.1.17.1.4',
      bsnDot11ResetProfileToDefault => '1.3.6.1.4.1.14179.2.1.17.1.40',
      bsnDot11QosAvgRealTimeDataRate => '1.3.6.1.4.1.14179.2.1.17.1.5',
      bsnDot11QosBurstRealTimeDataRate => '1.3.6.1.4.1.14179.2.1.17.1.6',
      bsnDot11QosMaxRFUsagePerAP => '1.3.6.1.4.1.14179.2.1.17.1.7',
      bsnDot11QosProfileQueueDepth => '1.3.6.1.4.1.14179.2.1.17.1.8',
      bsnDot11WiredQosProtocol => '1.3.6.1.4.1.14179.2.1.17.1.9',
      bsnTagTable => '1.3.6.1.4.1.14179.2.1.18',
      bsnTagEntry => '1.3.6.1.4.1.14179.2.1.18.1',
      bsnTagDot11MacAddress => '1.3.6.1.4.1.14179.2.1.18.1.1',
      bsnTagType => '1.3.6.1.4.1.14179.2.1.18.1.2',
      bsnTagLastReported => '1.3.6.1.4.1.14179.2.1.18.1.23',
      bsnTagTimeInterval => '1.3.6.1.4.1.14179.2.1.18.1.3',
      bsnTagBatteryStatus => '1.3.6.1.4.1.14179.2.1.18.1.4',
      bsnTagRssiDataTable => '1.3.6.1.4.1.14179.2.1.19',
      bsnTagRssiDataEntry => '1.3.6.1.4.1.14179.2.1.19.1',
      bsnTagRssiDataApMacAddress => '1.3.6.1.4.1.14179.2.1.19.1.1',
      bsnTagRssiDataApIfSlotId => '1.3.6.1.4.1.14179.2.1.19.1.2',
      bsnTagRssiDataSnr => '1.3.6.1.4.1.14179.2.1.19.1.26',
      bsnTagRssiDataApIfType => '1.3.6.1.4.1.14179.2.1.19.1.3',
      bsnTagRssiDataApName => '1.3.6.1.4.1.14179.2.1.19.1.4',
      bsnTagRssiDataLastHeard => '1.3.6.1.4.1.14179.2.1.19.1.5',
      bsnTagRssiData => '1.3.6.1.4.1.14179.2.1.19.1.6',
      bsnTagStatsTable => '1.3.6.1.4.1.14179.2.1.20',
      bsnTagStatsEntry => '1.3.6.1.4.1.14179.2.1.20.1',
      bsnTagBytesReceived => '1.3.6.1.4.1.14179.2.1.20.1.1',
      bsnTagPacketsReceived => '1.3.6.1.4.1.14179.2.1.20.1.20',
      bsnMobileStationExtStatsTable => '1.3.6.1.4.1.14179.2.1.21',
      bsnMobileStationExtStatsEntry => '1.3.6.1.4.1.14179.2.1.21.1',
      bsnMobileStationSampleTime => '1.3.6.1.4.1.14179.2.1.21.1.1',
      bsnMobileStationTxExcessiveRetries => '1.3.6.1.4.1.14179.2.1.21.1.2',
      bsnMobileStationTxFiltered => '1.3.6.1.4.1.14179.2.1.21.1.20',
      bsnMobileStationTxRetries => '1.3.6.1.4.1.14179.2.1.21.1.3',
      bsnMobileStationTable => '1.3.6.1.4.1.14179.2.1.4',
      bsnMobileStationEntry => '1.3.6.1.4.1.14179.2.1.4.1',
      bsnMobileStationMacAddress => '1.3.6.1.4.1.14179.2.1.4.1.1',
      bsnMobileStationReasonCode => '1.3.6.1.4.1.14179.2.1.4.1.10',
      bsnMobileStationMobilityStatus => '1.3.6.1.4.1.14179.2.1.4.1.11',
      bsnMobileStationAnchorAddress => '1.3.6.1.4.1.14179.2.1.4.1.12',
      bsnMobileStationCFPollable => '1.3.6.1.4.1.14179.2.1.4.1.13',
      bsnMobileStationCFPollRequest => '1.3.6.1.4.1.14179.2.1.4.1.14',
      bsnMobileStationChannelAgilityEnabled => '1.3.6.1.4.1.14179.2.1.4.1.15',
      bsnMobileStationPBCCOptionImplemented => '1.3.6.1.4.1.14179.2.1.4.1.16',
      bsnMobileStationShortPreambleOptionImplemented => '1.3.6.1.4.1.14179.2.1.4.1.17',
      bsnMobileStationSessionTimeout => '1.3.6.1.4.1.14179.2.1.4.1.18',
      bsnMobileStationAuthenticationAlgorithm => '1.3.6.1.4.1.14179.2.1.4.1.19',
      bsnMobileStationIpAddress => '1.3.6.1.4.1.14179.2.1.4.1.2',
      bsnMobileStationWepState => '1.3.6.1.4.1.14179.2.1.4.1.20',
      bsnMobileStationPortNumber => '1.3.6.1.4.1.14179.2.1.4.1.21',
      bsnMobileStationDeleteAction => '1.3.6.1.4.1.14179.2.1.4.1.22',
      bsnMobileStationPolicyManagerState => '1.3.6.1.4.1.14179.2.1.4.1.23',
      bsnMobileStationSecurityPolicyStatus => '1.3.6.1.4.1.14179.2.1.4.1.24',
      bsnMobileStationProtocol => '1.3.6.1.4.1.14179.2.1.4.1.25',
      bsnMobileStationMirrorMode => '1.3.6.1.4.1.14179.2.1.4.1.26',
      bsnMobileStationInterface => '1.3.6.1.4.1.14179.2.1.4.1.27',
      bsnMobileStationApMode => '1.3.6.1.4.1.14179.2.1.4.1.28',
      bsnMobileStationVlanId => '1.3.6.1.4.1.14179.2.1.4.1.29',
      bsnMobileStationUserName => '1.3.6.1.4.1.14179.2.1.4.1.3',
      bsnMobileStationPolicyType => '1.3.6.1.4.1.14179.2.1.4.1.30',
      bsnMobileStationEncryptionCypher => '1.3.6.1.4.1.14179.2.1.4.1.31',
      bsnMobileStationEapType => '1.3.6.1.4.1.14179.2.1.4.1.32',
      bsnMobileStationCcxVersion => '1.3.6.1.4.1.14179.2.1.4.1.33',
      bsnMobileStationE2eVersion => '1.3.6.1.4.1.14179.2.1.4.1.34',
      bsnMobileStationAPMacAddr => '1.3.6.1.4.1.14179.2.1.4.1.4',
      bsnMobileStationStatusCode => '1.3.6.1.4.1.14179.2.1.4.1.42',
      bsnMobileStationAPIfSlotId => '1.3.6.1.4.1.14179.2.1.4.1.5',
      bsnMobileStationEssIndex => '1.3.6.1.4.1.14179.2.1.4.1.6',
      bsnMobileStationSsid => '1.3.6.1.4.1.14179.2.1.4.1.7',
      bsnMobileStationAID => '1.3.6.1.4.1.14179.2.1.4.1.8',
      bsnMobileStationStatus => '1.3.6.1.4.1.14179.2.1.4.1.9',
      bsnMobileStationPerRadioPerVapTable => '1.3.6.1.4.1.14179.2.1.5',
      bsnMobileStationPerRadioPerVapEntry => '1.3.6.1.4.1.14179.2.1.5.1',
      bsnMobileStationPerRadioPerVapIndex => '1.3.6.1.4.1.14179.2.1.5.1.1',
      bsnMobileStationMacAddr => '1.3.6.1.4.1.14179.2.1.5.1.20',
      bsnMobileStationStatsTable => '1.3.6.1.4.1.14179.2.1.6',
      bsnMobileStationStatsEntry => '1.3.6.1.4.1.14179.2.1.6.1',
      bsnMobileStationRSSI => '1.3.6.1.4.1.14179.2.1.6.1.1',
      bsnMobileStationBytesReceived => '1.3.6.1.4.1.14179.2.1.6.1.2',
      bsnMobileStationSnr => '1.3.6.1.4.1.14179.2.1.6.1.26',
      bsnMobileStationBytesSent => '1.3.6.1.4.1.14179.2.1.6.1.3',
      bsnMobileStationPolicyErrors => '1.3.6.1.4.1.14179.2.1.6.1.4',
      bsnMobileStationPacketsReceived => '1.3.6.1.4.1.14179.2.1.6.1.5',
      bsnMobileStationPacketsSent => '1.3.6.1.4.1.14179.2.1.6.1.6',
      bsnRogueAPTable => '1.3.6.1.4.1.14179.2.1.7',
      bsnRogueAPEntry => '1.3.6.1.4.1.14179.2.1.7.1',
      bsnRogueAPDot11MacAddress => '1.3.6.1.4.1.14179.2.1.7.1.1',
      bsnRogueAPMaxDetectedRSSI => '1.3.6.1.4.1.14179.2.1.7.1.10',
      bsnRogueAPSSID => '1.3.6.1.4.1.14179.2.1.7.1.11',
      bsnRogueAPDetectingAPRadioType => '1.3.6.1.4.1.14179.2.1.7.1.12',
      bsnRogueAPDetectingAPMacAddress => '1.3.6.1.4.1.14179.2.1.7.1.13',
      bsnRogueAPMaxRssiRadioType => '1.3.6.1.4.1.14179.2.1.7.1.14',
      bsnRogueAPTotalDetectingAPs => '1.3.6.1.4.1.14179.2.1.7.1.2',
      bsnRogueAPState => '1.3.6.1.4.1.14179.2.1.7.1.24',
      bsnRogueAPClassType => '1.3.6.1.4.1.14179.2.1.7.1.25',
      bsnRogueAPChannel => '1.3.6.1.4.1.14179.2.1.7.1.26',
      bsnRogueAPDetectingAPName => '1.3.6.1.4.1.14179.2.1.7.1.27',
      bsnRogueAPFirstReported => '1.3.6.1.4.1.14179.2.1.7.1.3',
      bsnRogueAPLastReported => '1.3.6.1.4.1.14179.2.1.7.1.4',
      bsnRogueAPContainmentLevel => '1.3.6.1.4.1.14179.2.1.7.1.5',
      bsnRogueAPType => '1.3.6.1.4.1.14179.2.1.7.1.6',
      bsnRogueAPOnNetwork => '1.3.6.1.4.1.14179.2.1.7.1.7',
      bsnRogueAPTotalClients => '1.3.6.1.4.1.14179.2.1.7.1.8',
      bsnRogueAPRowStatus => '1.3.6.1.4.1.14179.2.1.7.1.9',
      bsnRogueAPAirespaceAPTable => '1.3.6.1.4.1.14179.2.1.8',
      bsnRogueAPAirespaceAPEntry => '1.3.6.1.4.1.14179.2.1.8.1',
      bsnRogueAPAirespaceAPMacAddress => '1.3.6.1.4.1.14179.2.1.8.1.1',
      bsnRogueAPContainmentChannels => '1.3.6.1.4.1.14179.2.1.8.1.10',
      bsnRogueAPAirespaceAPLastHeard => '1.3.6.1.4.1.14179.2.1.8.1.11',
      bsnRogueAPAirespaceAPWepMode => '1.3.6.1.4.1.14179.2.1.8.1.12',
      bsnRogueAPAirespaceAPPreamble => '1.3.6.1.4.1.14179.2.1.8.1.13',
      bsnRogueAPAirespaceAPWpaMode => '1.3.6.1.4.1.14179.2.1.8.1.14',
      bsnRogueAPAirespaceAPSlotId => '1.3.6.1.4.1.14179.2.1.8.1.2',
      bsnRogueAPAirespaceAPSNR => '1.3.6.1.4.1.14179.2.1.8.1.27',
      bsnRogueAPChannelWidth => '1.3.6.1.4.1.14179.2.1.8.1.28',
      bsnRogueAPRadioType => '1.3.6.1.4.1.14179.2.1.8.1.3',
      bsnRogueAPAirespaceAPName => '1.3.6.1.4.1.14179.2.1.8.1.4',
      bsnRogueAPChannelNumber => '1.3.6.1.4.1.14179.2.1.8.1.5',
      bsnRogueAPSsid => '1.3.6.1.4.1.14179.2.1.8.1.6',
      bsnRogueAPAirespaceAPRSSI => '1.3.6.1.4.1.14179.2.1.8.1.7',
      bsnRogueAPContainmentMode => '1.3.6.1.4.1.14179.2.1.8.1.8',
      bsnRogueAPContainmentChannelCount => '1.3.6.1.4.1.14179.2.1.8.1.9',
      bsnThirdPartyAPTable => '1.3.6.1.4.1.14179.2.1.9',
      bsnThirdPartyAPEntry => '1.3.6.1.4.1.14179.2.1.9.1',
      bsnThirdPartyAPMacAddress => '1.3.6.1.4.1.14179.2.1.9.1.1',
      bsnThirdPartyAPInterface => '1.3.6.1.4.1.14179.2.1.9.1.2',
      bsnThirdPartyAPRowStatus => '1.3.6.1.4.1.14179.2.1.9.1.24',
      bsnThirdPartyAPIpAddress => '1.3.6.1.4.1.14179.2.1.9.1.3',
      bsnThirdPartyAP802Dot1XRequired => '1.3.6.1.4.1.14179.2.1.9.1.4',
      bsnThirdPartyAPMirrorMode => '1.3.6.1.4.1.14179.2.1.9.1.5',
      bsnAPGroupsVlanConfig => '1.3.6.1.4.1.14179.2.10',
      bsnAPGroupsVlanFeature => '1.3.6.1.4.1.14179.2.10.1',
      bsnAPGroupsVlanTable => '1.3.6.1.4.1.14179.2.10.2',
      bsnAPGroupsVlanEntry => '1.3.6.1.4.1.14179.2.10.2.1',
      bsnAPGroupsVlanName => '1.3.6.1.4.1.14179.2.10.2.1.1',
      bsnAPGroupsVlanDescription => '1.3.6.1.4.1.14179.2.10.2.1.2',
      bsnAPGroupsVlanRowStatus => '1.3.6.1.4.1.14179.2.10.2.1.20',
      bsnAPGroupsVlanMappingTable => '1.3.6.1.4.1.14179.2.10.3',
      bsnAPGroupsVlanMappingEntry => '1.3.6.1.4.1.14179.2.10.3.1',
      bsnAPGroupsVlanMappingSsid => '1.3.6.1.4.1.14179.2.10.3.1.1',
      bsnAPGroupsVlanMappingInterfaceName => '1.3.6.1.4.1.14179.2.10.3.1.2',
      bsnAPGroupsVlanMappingRowStatus => '1.3.6.1.4.1.14179.2.10.3.1.20',
      bsnAP => '1.3.6.1.4.1.14179.2.2',
      bsnAPTable => '1.3.6.1.4.1.14179.2.2.1',
      bsnAPEntry => '1.3.6.1.4.1.14179.2.2.1.1',
      bsnAPDot3MacAddress => '1.3.6.1.4.1.14179.2.2.1.1.1',
      bsnAPPrimaryMwarName => '1.3.6.1.4.1.14179.2.2.1.1.10',
      bsnAPReset => '1.3.6.1.4.1.14179.2.2.1.1.11',
      bsnAPStatsTimer => '1.3.6.1.4.1.14179.2.2.1.1.12',
      bsnAPPortNumber => '1.3.6.1.4.1.14179.2.2.1.1.13',
      bsnAPModel => '1.3.6.1.4.1.14179.2.2.1.1.16',
      bsnAPSerialNumber => '1.3.6.1.4.1.14179.2.2.1.1.17',
      bsnAPClearConfig => '1.3.6.1.4.1.14179.2.2.1.1.18',
      bsnApIpAddress => '1.3.6.1.4.1.14179.2.2.1.1.19',
      bsnAPNumOfSlots => '1.3.6.1.4.1.14179.2.2.1.1.2',
      bsnAPMirrorMode => '1.3.6.1.4.1.14179.2.2.1.1.20',
      bsnAPRemoteModeSupport => '1.3.6.1.4.1.14179.2.2.1.1.21',
      bsnAPType => '1.3.6.1.4.1.14179.2.2.1.1.22',
      bsnAPTypeDefinition => {
      1 => 'ap1000',
      2 => 'ap1030',
      3 => 'mimo',
      4 => 'unknown',
      5 => 'ap1100',
      6 => 'ap1130',
      7 => 'ap1240',
      8 => 'ap1200',
      9 => 'ap1310',
      10 => 'ap1500',
      11 => 'ap1250',
      12 => 'ap1505',
      13 => 'ap3201',
      14 => 'ap1520',
      15 => 'ap800',
      16 => 'ap1140',
      17 => 'ap800agn',
      18 => 'ap3500i',
      19 => 'ap3500e',
      20 => 'ap1260',
      },
      bsnAPSecondaryMwarName => '1.3.6.1.4.1.14179.2.2.1.1.23',
      bsnAPTertiaryMwarName => '1.3.6.1.4.1.14179.2.2.1.1.24',
      bsnAPIsStaticIP => '1.3.6.1.4.1.14179.2.2.1.1.25',
      bsnAPNetmask => '1.3.6.1.4.1.14179.2.2.1.1.26',
      bsnAPGateway => '1.3.6.1.4.1.14179.2.2.1.1.27',
      bsnAPStaticIPAddress => '1.3.6.1.4.1.14179.2.2.1.1.28',
      bsnAPBridgingSupport => '1.3.6.1.4.1.14179.2.2.1.1.29',
      bsnAPName => '1.3.6.1.4.1.14179.2.2.1.1.3',
      bsnAPGroupVlanName => '1.3.6.1.4.1.14179.2.2.1.1.30',
      bsnAPIOSVersion => '1.3.6.1.4.1.14179.2.2.1.1.31',
      bsnAPCertificateType => '1.3.6.1.4.1.14179.2.2.1.1.32',
      bsnAPEthernetMacAddress => '1.3.6.1.4.1.14179.2.2.1.1.33',
      bsnAPAdminStatus => '1.3.6.1.4.1.14179.2.2.1.1.37',
      bsnAPLocation => '1.3.6.1.4.1.14179.2.2.1.1.4',
      bsnAPMonitorOnlyMode => '1.3.6.1.4.1.14179.2.2.1.1.5',
      bsnAPOperationStatus => '1.3.6.1.4.1.14179.2.2.1.1.6',
      bsnAPOperationStatusDefinition => {
          1 => 'associated',
          2 => 'disassociating',
          3 => 'downloading',
      },
      bsnAPSoftwareVersion => '1.3.6.1.4.1.14179.2.2.1.1.8',
      bsnAPBootVersion => '1.3.6.1.4.1.14179.2.2.1.1.9',
      bsnAPIfProfileThresholdConfigTable => '1.3.6.1.4.1.14179.2.2.12',
      bsnAPIfProfileThresholdConfigEntry => '1.3.6.1.4.1.14179.2.2.12.1',
      bsnAPIfProfileParamAssignment => '1.3.6.1.4.1.14179.2.2.12.1.1',
      bsnAPIfForeignInterferenceThreshold => '1.3.6.1.4.1.14179.2.2.12.1.2',
      bsnAPIfCoverageExceptionLevel => '1.3.6.1.4.1.14179.2.2.12.1.28',
      bsnAPIfForeignNoiseThreshold => '1.3.6.1.4.1.14179.2.2.12.1.3',
      bsnAPIfRFUtilizationThreshold => '1.3.6.1.4.1.14179.2.2.12.1.4',
      bsnAPIfThroughputThreshold => '1.3.6.1.4.1.14179.2.2.12.1.5',
      bsnAPIfMobilesThreshold => '1.3.6.1.4.1.14179.2.2.12.1.6',
      bsnAPIfCoverageThreshold => '1.3.6.1.4.1.14179.2.2.12.1.7',
      bsnAPIfMobileMinExceptionLevel => '1.3.6.1.4.1.14179.2.2.12.1.8',
      bsnAPIfLoadParametersTable => '1.3.6.1.4.1.14179.2.2.13',
      bsnAPIfLoadParametersEntry => '1.3.6.1.4.1.14179.2.2.13.1',
      bsnAPIfLoadRxUtilization => '1.3.6.1.4.1.14179.2.2.13.1.1',
      bsnAPIfLoadTxUtilization => '1.3.6.1.4.1.14179.2.2.13.1.2',
      bsnAPIfPoorSNRClients => '1.3.6.1.4.1.14179.2.2.13.1.24',
      bsnAPIfLoadChannelUtilization => '1.3.6.1.4.1.14179.2.2.13.1.3',
      bsnAPIfLoadNumOfClients => '1.3.6.1.4.1.14179.2.2.13.1.4',
      bsnAPIfChannelInterferenceInfoTable => '1.3.6.1.4.1.14179.2.2.14',
      bsnAPIfChannelInterferenceInfoEntry => '1.3.6.1.4.1.14179.2.2.14.1',
      bsnAPIfInterferenceChannelNo => '1.3.6.1.4.1.14179.2.2.14.1.1',
      bsnAPIfInterferencePower => '1.3.6.1.4.1.14179.2.2.14.1.2',
      bsnAPIfInterferenceUtilization => '1.3.6.1.4.1.14179.2.2.14.1.22',
      bsnAPIfChannelNoiseInfoTable => '1.3.6.1.4.1.14179.2.2.15',
      bsnAPIfChannelNoiseInfoEntry => '1.3.6.1.4.1.14179.2.2.15.1',
      bsnAPIfNoiseChannelNo => '1.3.6.1.4.1.14179.2.2.15.1.1',
      bsnAPIfDBNoisePower => '1.3.6.1.4.1.14179.2.2.15.1.21',
      bsnAPIfProfileStateTable => '1.3.6.1.4.1.14179.2.2.16',
      bsnAPIfProfileStateEntry => '1.3.6.1.4.1.14179.2.2.16.1',
      bsnAPIfLoadProfileState => '1.3.6.1.4.1.14179.2.2.16.1.1',
      bsnAPIfInterferenceProfileState => '1.3.6.1.4.1.14179.2.2.16.1.2',
      bsnAPIfCoverageProfileState => '1.3.6.1.4.1.14179.2.2.16.1.24',
      bsnAPIfNoiseProfileState => '1.3.6.1.4.1.14179.2.2.16.1.3',
      bsnAPIfRxNeighborsTable => '1.3.6.1.4.1.14179.2.2.17',
      bsnAPIfRxNeighborsEntry => '1.3.6.1.4.1.14179.2.2.17.1',
      bsnAPIfRxNeighborMacAddress => '1.3.6.1.4.1.14179.2.2.17.1.1',
      bsnAPIfRxNeighborIpAddress => '1.3.6.1.4.1.14179.2.2.17.1.2',
      bsnAPIfRxNeighborSlot => '1.3.6.1.4.1.14179.2.2.17.1.24',
      bsnAPIfRxNeighborChannel => '1.3.6.1.4.1.14179.2.2.17.1.26',
      bsnAPIfRxNeighborChannelWidth => '1.3.6.1.4.1.14179.2.2.17.1.27',
      bsnAPIfRxNeighborRSSI => '1.3.6.1.4.1.14179.2.2.17.1.3',
      bsnAPIfStationRSSICoverageInfoTable => '1.3.6.1.4.1.14179.2.2.18',
      bsnAPIfStationRSSICoverageInfoEntry => '1.3.6.1.4.1.14179.2.2.18.1',
      bsnAPIfStationRSSICoverageIndex => '1.3.6.1.4.1.14179.2.2.18.1.1',
      bsnAPIfRSSILevel => '1.3.6.1.4.1.14179.2.2.18.1.2',
      bsnAPIfStationCountOnRSSI => '1.3.6.1.4.1.14179.2.2.18.1.23',
      bsnAPIfStationSNRCoverageInfoTable => '1.3.6.1.4.1.14179.2.2.19',
      bsnAPIfStationSNRCoverageInfoEntry => '1.3.6.1.4.1.14179.2.2.19.1',
      bsnAPIfStationSNRCoverageIndex => '1.3.6.1.4.1.14179.2.2.19.1.1',
      bsnAPIfSNRLevel => '1.3.6.1.4.1.14179.2.2.19.1.2',
      bsnAPIfStationCountOnSNR => '1.3.6.1.4.1.14179.2.2.19.1.23',
      bsnAPIfTable => '1.3.6.1.4.1.14179.2.2.2',
      bsnAPIfEntry => '1.3.6.1.4.1.14179.2.2.2.1',
      bsnAPIfSlotId => '1.3.6.1.4.1.14179.2.2.2.1.1',
      bsnAPIfCellSiteConfigId => '1.3.6.1.4.1.14179.2.2.2.1.10',
      bsnAPIfNumberOfVaps => '1.3.6.1.4.1.14179.2.2.2.1.11',
      bsnAPIfOperStatus => '1.3.6.1.4.1.14179.2.2.2.1.12',
      bsnAPIfPortNumber => '1.3.6.1.4.1.14179.2.2.2.1.13',
      bsnAPIfPhyAntennaOptions => '1.3.6.1.4.1.14179.2.2.2.1.14',
      bsnApIfNoOfUsers => '1.3.6.1.4.1.14179.2.2.2.1.15',
      bsnAPIfWlanOverride => '1.3.6.1.4.1.14179.2.2.2.1.16',
      bsnAPIfPacketsSniffingFeature => '1.3.6.1.4.1.14179.2.2.2.1.17',
      bsnAPIfSniffChannel => '1.3.6.1.4.1.14179.2.2.2.1.18',
      bsnAPIfSniffServerIPAddress => '1.3.6.1.4.1.14179.2.2.2.1.19',
      bsnAPIfType => '1.3.6.1.4.1.14179.2.2.2.1.2',
      bsnAPIfAntennaGain => '1.3.6.1.4.1.14179.2.2.2.1.20',
      bsnAPIfChannelList => '1.3.6.1.4.1.14179.2.2.2.1.21',
      bsnAPIfAbsolutePowerList => '1.3.6.1.4.1.14179.2.2.2.1.22',
      bsnAPIfRegulatoryDomainSupport => '1.3.6.1.4.1.14179.2.2.2.1.23',
      bsnAPIfPhyChannelAssignment => '1.3.6.1.4.1.14179.2.2.2.1.3',
      bsnAPIfAdminStatus => '1.3.6.1.4.1.14179.2.2.2.1.34',
      bsnAPIfPhyChannelNumber => '1.3.6.1.4.1.14179.2.2.2.1.4',
      bsnAPIfPhyTxPowerControl => '1.3.6.1.4.1.14179.2.2.2.1.5',
      bsnAPIfPhyTxPowerLevel => '1.3.6.1.4.1.14179.2.2.2.1.6',
      bsnAPIfPhyAntennaMode => '1.3.6.1.4.1.14179.2.2.2.1.7',
      bsnAPIfPhyAntennaType => '1.3.6.1.4.1.14179.2.2.2.1.8',
      bsnAPIfPhyAntennaDiversity => '1.3.6.1.4.1.14179.2.2.2.1.9',
      bsnAPIfRecommendedRFParametersTable => '1.3.6.1.4.1.14179.2.2.20',
      bsnAPIfRecommendedRFParametersEntry => '1.3.6.1.4.1.14179.2.2.20.1',
      bsnAPIfRecommendedChannelNumber => '1.3.6.1.4.1.14179.2.2.20.1.1',
      bsnAPIfRecommendedTxPowerLevel => '1.3.6.1.4.1.14179.2.2.20.1.2',
      bsnAPIfRecommendedFragmentationThreshold => '1.3.6.1.4.1.14179.2.2.20.1.24',
      bsnAPIfRecommendedRTSThreshold => '1.3.6.1.4.1.14179.2.2.20.1.3',
      bsnAPIfWlanOverrideTable => '1.3.6.1.4.1.14179.2.2.21',
      bsnAPIfWlanOverrideEntry => '1.3.6.1.4.1.14179.2.2.21.1',
      bsnAPIfWlanOverrideId => '1.3.6.1.4.1.14179.2.2.21.1.1',
      bsnAPIfWlanOverrideRowStatus => '1.3.6.1.4.1.14179.2.2.21.1.15',
      bsnAPIfWlanOverrideSsid => '1.3.6.1.4.1.14179.2.2.21.1.2',
      bsnMeshNodeTable => '1.3.6.1.4.1.14179.2.2.22',
      bsnMeshNodeEntry => '1.3.6.1.4.1.14179.2.2.22.1',
      bsnMeshNodeRole => '1.3.6.1.4.1.14179.2.2.22.1.1',
      bsnMeshNodePoorNeighSnr => '1.3.6.1.4.1.14179.2.2.22.1.10',
      bsnMeshNodeBlacklistPackets => '1.3.6.1.4.1.14179.2.2.22.1.11',
      bsnMeshNodeInsufficientMemory => '1.3.6.1.4.1.14179.2.2.22.1.12',
      bsnMeshNodeRxNeighReq => '1.3.6.1.4.1.14179.2.2.22.1.13',
      bsnMeshNodeRxNeighRsp => '1.3.6.1.4.1.14179.2.2.22.1.14',
      bsnMeshNodeTxNeighReq => '1.3.6.1.4.1.14179.2.2.22.1.15',
      bsnMeshNodeTxNeighRsp => '1.3.6.1.4.1.14179.2.2.22.1.16',
      bsnMeshNodeParentChanges => '1.3.6.1.4.1.14179.2.2.22.1.17',
      bsnMeshNodeNeighTimeout => '1.3.6.1.4.1.14179.2.2.22.1.18',
      bsnMeshNodeParentMacAddress => '1.3.6.1.4.1.14179.2.2.22.1.19',
      bsnMeshNodeGroup => '1.3.6.1.4.1.14179.2.2.22.1.2',
      bsnMeshNodeAPType => '1.3.6.1.4.1.14179.2.2.22.1.20',
      bsnMeshNodeEthernetBridge => '1.3.6.1.4.1.14179.2.2.22.1.21',
      bsnMeshNodeBackhaul => '1.3.6.1.4.1.14179.2.2.22.1.3',
      bsnMeshNodeHops => '1.3.6.1.4.1.14179.2.2.22.1.30',
      bsnMeshNodeBackhaulPAP => '1.3.6.1.4.1.14179.2.2.22.1.4',
      bsnMeshNodeBackhaulRAP => '1.3.6.1.4.1.14179.2.2.22.1.5',
      bsnMeshNodeDataRate => '1.3.6.1.4.1.14179.2.2.22.1.6',
      bsnMeshNodeChannel => '1.3.6.1.4.1.14179.2.2.22.1.7',
      bsnMeshNodeRoutingState => '1.3.6.1.4.1.14179.2.2.22.1.8',
      bsnMeshNodeMalformedNeighPackets => '1.3.6.1.4.1.14179.2.2.22.1.9',
      bsnMeshNeighsTable => '1.3.6.1.4.1.14179.2.2.23',
      bsnMeshNeighsEntry => '1.3.6.1.4.1.14179.2.2.23.1',
      bsnMeshNeighMacAddress => '1.3.6.1.4.1.14179.2.2.23.1.1',
      bsnMeshNeighRapEase => '1.3.6.1.4.1.14179.2.2.23.1.10',
      bsnMeshNeighTxParent => '1.3.6.1.4.1.14179.2.2.23.1.11',
      bsnMeshNeighRxParent => '1.3.6.1.4.1.14179.2.2.23.1.12',
      bsnMeshNeighPoorSnr => '1.3.6.1.4.1.14179.2.2.23.1.13',
      bsnMeshNeighLastUpdate => '1.3.6.1.4.1.14179.2.2.23.1.14',
      bsnMeshNeighType => '1.3.6.1.4.1.14179.2.2.23.1.2',
      bsnMeshNeighParentChange => '1.3.6.1.4.1.14179.2.2.23.1.20',
      bsnMeshNeighState => '1.3.6.1.4.1.14179.2.2.23.1.3',
      bsnMeshNeighSnr => '1.3.6.1.4.1.14179.2.2.23.1.4',
      bsnMeshNeighSnrUp => '1.3.6.1.4.1.14179.2.2.23.1.5',
      bsnMeshNeighSnrDown => '1.3.6.1.4.1.14179.2.2.23.1.6',
      bsnMeshNeighLinkSnr => '1.3.6.1.4.1.14179.2.2.23.1.7',
      bsnMeshNeighAdjustedEase => '1.3.6.1.4.1.14179.2.2.23.1.8',
      bsnMeshNeighUnadjustedEase => '1.3.6.1.4.1.14179.2.2.23.1.9',
      bsnAPIfRadarChannelStatisticsTable => '1.3.6.1.4.1.14179.2.2.24',
      bsnAPIfRadarChannelStatisticsEntry => '1.3.6.1.4.1.14179.2.2.24.1',
      bsnAPIfRadarDetectedChannelNumber => '1.3.6.1.4.1.14179.2.2.24.1.1',
      bsnAPIfRadarSignalLastHeard => '1.3.6.1.4.1.14179.2.2.24.1.2',
      bsnAPIfSmtParamTable => '1.3.6.1.4.1.14179.2.2.3',
      bsnAPIfSmtParamEntry => '1.3.6.1.4.1.14179.2.2.3.1',
      bsnAPIfDot11BeaconPeriod => '1.3.6.1.4.1.14179.2.2.3.1.1',
      bsnAPIfDot11SmtParamsConfigType => '1.3.6.1.4.1.14179.2.2.3.1.10',
      bsnAPIfDot11MediumOccupancyLimit => '1.3.6.1.4.1.14179.2.2.3.1.2',
      bsnAPIfDot11CFPPeriod => '1.3.6.1.4.1.14179.2.2.3.1.3',
      bsnAPIfDot11BSSID => '1.3.6.1.4.1.14179.2.2.3.1.30',
      bsnAPIfDot11CFPMaxDuration => '1.3.6.1.4.1.14179.2.2.3.1.4',
      bsnAPIfDot11OperationalRateSet => '1.3.6.1.4.1.14179.2.2.3.1.5',
      bsnAPIfDot11DTIMPeriod => '1.3.6.1.4.1.14179.2.2.3.1.6',
      bsnAPIfDot11MultiDomainCapabilityImplemented => '1.3.6.1.4.1.14179.2.2.3.1.7',
      bsnAPIfDot11MultiDomainCapabilityEnabled => '1.3.6.1.4.1.14179.2.2.3.1.8',
      bsnAPIfDot11CountryString => '1.3.6.1.4.1.14179.2.2.3.1.9',
      bsnAPIfMultiDomainCapabilityTable => '1.3.6.1.4.1.14179.2.2.4',
      bsnAPIfMultiDomainCapabilityEntry => '1.3.6.1.4.1.14179.2.2.4.1',
      bsnAPIfDot11MaximumTransmitPowerLevel => '1.3.6.1.4.1.14179.2.2.4.1.1',
      bsnAPIfDot11FirstChannelNumber => '1.3.6.1.4.1.14179.2.2.4.1.2',
      bsnAPIfDot11NumberofChannels => '1.3.6.1.4.1.14179.2.2.4.1.20',
      bsnAPIfMacOperationParamTable => '1.3.6.1.4.1.14179.2.2.5',
      bsnAPIfMacOperationParamEntry => '1.3.6.1.4.1.14179.2.2.5.1',
      bsnAPIfDot11MacRTSThreshold => '1.3.6.1.4.1.14179.2.2.5.1.1',
      bsnAPIfDot11MacShortRetryLimit => '1.3.6.1.4.1.14179.2.2.5.1.2',
      bsnAPIfDot11MacMaxReceiveLifetime => '1.3.6.1.4.1.14179.2.2.5.1.25',
      bsnAPIfDot11MacLongRetryLimit => '1.3.6.1.4.1.14179.2.2.5.1.3',
      bsnAPIfDot11MacFragmentationThreshold => '1.3.6.1.4.1.14179.2.2.5.1.4',
      bsnAPIfDot11MacMaxTransmitMSDULifetime => '1.3.6.1.4.1.14179.2.2.5.1.5',
      bsnAPIfDot11MacParamsConfigType => '1.3.6.1.4.1.14179.2.2.5.1.6',
      bsnAPIfDot11CountersTable => '1.3.6.1.4.1.14179.2.2.6',
      bsnAPIfDot11CountersEntry => '1.3.6.1.4.1.14179.2.2.6.1',
      bsnAPIfDot11TransmittedFragmentCount => '1.3.6.1.4.1.14179.2.2.6.1.1',
      bsnAPIfDot11MulticastReceivedFrameCount => '1.3.6.1.4.1.14179.2.2.6.1.10',
      bsnAPIfDot11FCSErrorCount => '1.3.6.1.4.1.14179.2.2.6.1.11',
      bsnAPIfDot11TransmittedFrameCount => '1.3.6.1.4.1.14179.2.2.6.1.12',
      bsnAPIfDot11WEPUndecryptableCount => '1.3.6.1.4.1.14179.2.2.6.1.13',
      bsnAPIfDot11MulticastTransmittedFrameCount => '1.3.6.1.4.1.14179.2.2.6.1.2',
      bsnAPIfDot11RetryCount => '1.3.6.1.4.1.14179.2.2.6.1.3',
      bsnAPIfDot11FailedCount => '1.3.6.1.4.1.14179.2.2.6.1.33',
      bsnAPIfDot11MultipleRetryCount => '1.3.6.1.4.1.14179.2.2.6.1.4',
      bsnAPIfDot11FrameDuplicateCount => '1.3.6.1.4.1.14179.2.2.6.1.5',
      bsnAPIfDot11RTSSuccessCount => '1.3.6.1.4.1.14179.2.2.6.1.6',
      bsnAPIfDot11RTSFailureCount => '1.3.6.1.4.1.14179.2.2.6.1.7',
      bsnAPIfDot11ACKFailureCount => '1.3.6.1.4.1.14179.2.2.6.1.8',
      bsnAPIfDot11ReceivedFragmentCount => '1.3.6.1.4.1.14179.2.2.6.1.9',
      bsnAPIfDot11PhyTxPowerTable => '1.3.6.1.4.1.14179.2.2.8',
      bsnAPIfDot11PhyTxPowerEntry => '1.3.6.1.4.1.14179.2.2.8.1',
      bsnAPIfDot11NumberSupportedPowerLevels => '1.3.6.1.4.1.14179.2.2.8.1.1',
      bsnAPIfDot11TxPowerLevel1 => '1.3.6.1.4.1.14179.2.2.8.1.2',
      bsnAPIfDot11TxPowerLevel8 => '1.3.6.1.4.1.14179.2.2.8.1.28',
      bsnAPIfDot11TxPowerLevel2 => '1.3.6.1.4.1.14179.2.2.8.1.3',
      bsnAPIfDot11TxPowerLevel3 => '1.3.6.1.4.1.14179.2.2.8.1.4',
      bsnAPIfDot11TxPowerLevel4 => '1.3.6.1.4.1.14179.2.2.8.1.5',
      bsnAPIfDot11TxPowerLevel5 => '1.3.6.1.4.1.14179.2.2.8.1.6',
      bsnAPIfDot11TxPowerLevel6 => '1.3.6.1.4.1.14179.2.2.8.1.7',
      bsnAPIfDot11TxPowerLevel7 => '1.3.6.1.4.1.14179.2.2.8.1.8',
      bsnAPIfDot11PhyChannelTable => '1.3.6.1.4.1.14179.2.2.9',
      bsnAPIfDot11PhyChannelEntry => '1.3.6.1.4.1.14179.2.2.9.1',
      bsnAPIfDot11CurrentCCAMode => '1.3.6.1.4.1.14179.2.2.9.1.1',
      bsnAPIfDot11EDThreshold => '1.3.6.1.4.1.14179.2.2.9.1.2',
      bsnAPIfDot11TIThreshold => '1.3.6.1.4.1.14179.2.2.9.1.23',
      bsnGlobalDot11 => '1.3.6.1.4.1.14179.2.3',
      bsnGlobalDot11Config => '1.3.6.1.4.1.14179.2.3.1',
      bsnGlobalDot11PrivacyOptionImplemented => '1.3.6.1.4.1.14179.2.3.1.1',
      bsnSystemCurrentTime => '1.3.6.1.4.1.14179.2.3.1.10',
      bsnUpdateSystemTime => '1.3.6.1.4.1.14179.2.3.1.11',
      bsnOperatingTemperatureEnvironment => '1.3.6.1.4.1.14179.2.3.1.12',
      bsnOperatingTemperatureEnvironmentDefinition => {
          0 => 'unknown',
          1 => 'commercial', # 0 - 40
          2 => 'industrial', # -10 - 70
      },
      bsnSensorTemperature => '1.3.6.1.4.1.14179.2.3.1.13',
      bsnTemperatureAlarmLowLimit => '1.3.6.1.4.1.14179.2.3.1.14',
      bsnTemperatureAlarmHighLimit => '1.3.6.1.4.1.14179.2.3.1.15',
      bsnVirtualGatewayAddress => '1.3.6.1.4.1.14179.2.3.1.16',
      bsnRFMobilityDomainName => '1.3.6.1.4.1.14179.2.3.1.17',
      bsnClientWatchListFeature => '1.3.6.1.4.1.14179.2.3.1.18',
      bsnRogueLocationDiscoveryProtocol => '1.3.6.1.4.1.14179.2.3.1.19',
      bsnGlobalDot11AuthenticationResponseTimeOut => '1.3.6.1.4.1.14179.2.3.1.2',
      bsnRogueAutoContainFeature => '1.3.6.1.4.1.14179.2.3.1.20',
      bsnOverAirProvisionApMode => '1.3.6.1.4.1.14179.2.3.1.21',
      bsnMaximumNumberOfConcurrentLogins => '1.3.6.1.4.1.14179.2.3.1.22',
      bsnAutoContainRoguesAdvertisingSsid => '1.3.6.1.4.1.14179.2.3.1.23',
      bsnAutoContainAdhocNetworks => '1.3.6.1.4.1.14179.2.3.1.24',
      bsnAutoContainTrustedClientsOnRogueAps => '1.3.6.1.4.1.14179.2.3.1.25',
      bsnValidateRogueClientsAgainstAAA => '1.3.6.1.4.1.14179.2.3.1.26',
      bsnSystemTimezoneDelta => '1.3.6.1.4.1.14179.2.3.1.27',
      bsnSystemTimezoneDaylightSavings => '1.3.6.1.4.1.14179.2.3.1.28',
      bsnAllowAuthorizeApAgainstAAA => '1.3.6.1.4.1.14179.2.3.1.29',
      bsnGlobalDot11MultiDomainCapabilityImplemented => '1.3.6.1.4.1.14179.2.3.1.3',
      bsnSystemTimezoneDeltaMinutes => '1.3.6.1.4.1.14179.2.3.1.30',
      bsnApFallbackEnabled => '1.3.6.1.4.1.14179.2.3.1.31',
      bsnAppleTalkEnabled => '1.3.6.1.4.1.14179.2.3.1.32',
      bsnGlobalDot11MultiDomainCapabilityEnabled => '1.3.6.1.4.1.14179.2.3.1.4',
      bsnTrustedApPolicyConfig => '1.3.6.1.4.1.14179.2.3.1.40',
      bsnPolicyForMisconfiguredAps => '1.3.6.1.4.1.14179.2.3.1.40.1',
      bsnEncryptionPolicyEnforced => '1.3.6.1.4.1.14179.2.3.1.40.2',
      bsnPreamblePolicyEnforced => '1.3.6.1.4.1.14179.2.3.1.40.3',
      bsnDot11ModePolicyEnforced => '1.3.6.1.4.1.14179.2.3.1.40.4',
      bsnRadioTypePolicyEnforced => '1.3.6.1.4.1.14179.2.3.1.40.5',
      bsnValidateSsidForTrustedAp => '1.3.6.1.4.1.14179.2.3.1.40.6',
      bsnAlertIfTrustedApMissing => '1.3.6.1.4.1.14179.2.3.1.40.7',
      bsnTrustedApEntryExpirationTimeout => '1.3.6.1.4.1.14179.2.3.1.40.8',
      bsnClientExclusionPolicyConfig => '1.3.6.1.4.1.14179.2.3.1.41',
      bsnExcessive80211AssocFailures => '1.3.6.1.4.1.14179.2.3.1.41.1',
      bsnExcessive80211AuthFailures => '1.3.6.1.4.1.14179.2.3.1.41.2',
      bsnExcessive8021xAuthFailures => '1.3.6.1.4.1.14179.2.3.1.41.3',
      bsnExternalPolicyServerFailures => '1.3.6.1.4.1.14179.2.3.1.41.4',
      bsnExcessiveWebAuthFailures => '1.3.6.1.4.1.14179.2.3.1.41.5',
      bsnIPTheftORReuse => '1.3.6.1.4.1.14179.2.3.1.41.6',
      bsnSignatureConfig => '1.3.6.1.4.1.14179.2.3.1.42',
      bsnStandardSignatureTable => '1.3.6.1.4.1.14179.2.3.1.42.1',
      bsnStandardSignatureEntry => '1.3.6.1.4.1.14179.2.3.1.42.1.1',
      bsnStandardSignaturePrecedence => '1.3.6.1.4.1.14179.2.3.1.42.1.1.1',
      bsnStandardSignatureConfigType => '1.3.6.1.4.1.14179.2.3.1.42.1.1.10',
      bsnStandardSignatureEnable => '1.3.6.1.4.1.14179.2.3.1.42.1.1.11',
      bsnStandardSignatureMacInfo => '1.3.6.1.4.1.14179.2.3.1.42.1.1.12',
      bsnStandardSignatureMacFreq => '1.3.6.1.4.1.14179.2.3.1.42.1.1.13',
      bsnStandardSignatureName => '1.3.6.1.4.1.14179.2.3.1.42.1.1.2',
      bsnStandardSignatureRowStatus => '1.3.6.1.4.1.14179.2.3.1.42.1.1.20',
      bsnStandardSignatureInterval => '1.3.6.1.4.1.14179.2.3.1.42.1.1.21',
      bsnStandardSignatureDescription => '1.3.6.1.4.1.14179.2.3.1.42.1.1.3',
      bsnStandardSignatureFrameType => '1.3.6.1.4.1.14179.2.3.1.42.1.1.4',
      bsnStandardSignatureAction => '1.3.6.1.4.1.14179.2.3.1.42.1.1.5',
      bsnStandardSignatureState => '1.3.6.1.4.1.14179.2.3.1.42.1.1.6',
      bsnStandardSignatureFrequency => '1.3.6.1.4.1.14179.2.3.1.42.1.1.7',
      bsnStandardSignatureQuietTime => '1.3.6.1.4.1.14179.2.3.1.42.1.1.8',
      bsnStandardSignatureVersion => '1.3.6.1.4.1.14179.2.3.1.42.1.1.9',
      bsnStandardSignaturePatternTable => '1.3.6.1.4.1.14179.2.3.1.42.2',
      bsnStandardSignaturePatternEntry => '1.3.6.1.4.1.14179.2.3.1.42.2.1',
      bsnStandardSignaturePatternIndex => '1.3.6.1.4.1.14179.2.3.1.42.2.1.1',
      bsnStandardSignaturePatternRowStatus => '1.3.6.1.4.1.14179.2.3.1.42.2.1.15',
      bsnStandardSignaturePatternOffset => '1.3.6.1.4.1.14179.2.3.1.42.2.1.2',
      bsnStandardSignaturePatternString => '1.3.6.1.4.1.14179.2.3.1.42.2.1.3',
      bsnStandardSignaturePatternMask => '1.3.6.1.4.1.14179.2.3.1.42.2.1.4',
      bsnStandardSignaturePatternOffSetStart => '1.3.6.1.4.1.14179.2.3.1.42.2.1.5',
      bsnCustomSignatureTable => '1.3.6.1.4.1.14179.2.3.1.42.3',
      bsnCustomSignatureEntry => '1.3.6.1.4.1.14179.2.3.1.42.3.1',
      bsnCustomSignaturePrecedence => '1.3.6.1.4.1.14179.2.3.1.42.3.1.1',
      bsnCustomSignatureConfigType => '1.3.6.1.4.1.14179.2.3.1.42.3.1.10',
      bsnCustomSignatureEnable => '1.3.6.1.4.1.14179.2.3.1.42.3.1.11',
      bsnCustomSignatureMacInfo => '1.3.6.1.4.1.14179.2.3.1.42.3.1.12',
      bsnCustomSignatureMacFreq => '1.3.6.1.4.1.14179.2.3.1.42.3.1.13',
      bsnCustomSignatureName => '1.3.6.1.4.1.14179.2.3.1.42.3.1.2',
      bsnCustomSignatureRowStatus => '1.3.6.1.4.1.14179.2.3.1.42.3.1.20',
      bsnCustomSignatureInterval => '1.3.6.1.4.1.14179.2.3.1.42.3.1.21',
      bsnCustomSignatureDescription => '1.3.6.1.4.1.14179.2.3.1.42.3.1.3',
      bsnCustomSignatureFrameType => '1.3.6.1.4.1.14179.2.3.1.42.3.1.4',
      bsnCustomSignatureAction => '1.3.6.1.4.1.14179.2.3.1.42.3.1.5',
      bsnCustomSignatureState => '1.3.6.1.4.1.14179.2.3.1.42.3.1.6',
      bsnCustomSignatureFrequency => '1.3.6.1.4.1.14179.2.3.1.42.3.1.7',
      bsnCustomSignatureQuietTime => '1.3.6.1.4.1.14179.2.3.1.42.3.1.8',
      bsnCustomSignatureVersion => '1.3.6.1.4.1.14179.2.3.1.42.3.1.9',
      bsnCustomSignaturePatternTable => '1.3.6.1.4.1.14179.2.3.1.42.4',
      bsnCustomSignaturePatternEntry => '1.3.6.1.4.1.14179.2.3.1.42.4.1',
      bsnCustomSignaturePatternIndex => '1.3.6.1.4.1.14179.2.3.1.42.4.1.1',
      bsnCustomSignaturePatternRowStatus => '1.3.6.1.4.1.14179.2.3.1.42.4.1.15',
      bsnCustomSignaturePatternOffset => '1.3.6.1.4.1.14179.2.3.1.42.4.1.2',
      bsnCustomSignaturePatternString => '1.3.6.1.4.1.14179.2.3.1.42.4.1.3',
      bsnCustomSignaturePatternMask => '1.3.6.1.4.1.14179.2.3.1.42.4.1.4',
      bsnCustomSignaturePatternOffSetStart => '1.3.6.1.4.1.14179.2.3.1.42.4.1.5',
      bsnSignatureCheckState => '1.3.6.1.4.1.14179.2.3.1.42.5',
      bsnRfIdTagConfig => '1.3.6.1.4.1.14179.2.3.1.43',
      bsnRfIdTagStatus => '1.3.6.1.4.1.14179.2.3.1.43.1',
      bsnRfIdTagDataTimeout => '1.3.6.1.4.1.14179.2.3.1.43.2',
      bsnRfIdTagAutoTimeoutStatus => '1.3.6.1.4.1.14179.2.3.1.43.3',
      bsnAPNeighborAuthConfig => '1.3.6.1.4.1.14179.2.3.1.44',
      bsnAPNeighborAuthStatus => '1.3.6.1.4.1.14179.2.3.1.44.1',
      bsnAPNeighborAuthAlarmThreshold => '1.3.6.1.4.1.14179.2.3.1.44.2',
      bsnRFNetworkName => '1.3.6.1.4.1.14179.2.3.1.45',
      bsnFastSSIDChangeFeature => '1.3.6.1.4.1.14179.2.3.1.46',
      bsnBridgingPolicyConfig => '1.3.6.1.4.1.14179.2.3.1.47',
      bsnBridgingZeroTouchConfig => '1.3.6.1.4.1.14179.2.3.1.47.1',
      bsnBridgingSharedSecretKey => '1.3.6.1.4.1.14179.2.3.1.47.2',
      bsnAcceptSelfSignedCertificate => '1.3.6.1.4.1.14179.2.3.1.48',
      bsnSystemClockTime => '1.3.6.1.4.1.14179.2.3.1.49',
      bsnGlobalDot11CountryIndex => '1.3.6.1.4.1.14179.2.3.1.5',
      bsnGlobalDot11LoadBalancing => '1.3.6.1.4.1.14179.2.3.1.6',
      bsnGlobalDot11RogueTimer => '1.3.6.1.4.1.14179.2.3.1.7',
      bsnPrimaryMwarForAPs => '1.3.6.1.4.1.14179.2.3.1.8',
      bsnRtpProtocolPriority => '1.3.6.1.4.1.14179.2.3.1.9',
      bsnGlobalDot11b => '1.3.6.1.4.1.14179.2.3.2',
      bsnGlobalDot11bConfig => '1.3.6.1.4.1.14179.2.3.2.1',
      bsnGlobalDot11bNetworkStatus => '1.3.6.1.4.1.14179.2.3.2.1.1',
      bsnGlobalDot11bDynamicTxPowerControlInterval => '1.3.6.1.4.1.14179.2.3.2.1.10',
      bsnGlobalDot11bCurrentTxPowerLevel => '1.3.6.1.4.1.14179.2.3.2.1.11',
      bsnGlobalDot11bInputsForDTP => '1.3.6.1.4.1.14179.2.3.2.1.12',
      bsnGlobalDot11bPowerUpdateCmdInvoke => '1.3.6.1.4.1.14179.2.3.2.1.13',
      bsnGlobalDot11bPowerUpdateCmdStatus => '1.3.6.1.4.1.14179.2.3.2.1.14',
      bsnGlobalDot11bDataRate1Mhz => '1.3.6.1.4.1.14179.2.3.2.1.15',
      bsnGlobalDot11bDataRate2Mhz => '1.3.6.1.4.1.14179.2.3.2.1.16',
      bsnGlobalDot11bDataRate5AndHalfMhz => '1.3.6.1.4.1.14179.2.3.2.1.17',
      bsnGlobalDot11bDataRate11Mhz => '1.3.6.1.4.1.14179.2.3.2.1.18',
      bsnGlobalDot11bShortPreamble => '1.3.6.1.4.1.14179.2.3.2.1.19',
      bsnGlobalDot11bBeaconPeriod => '1.3.6.1.4.1.14179.2.3.2.1.2',
      bsnGlobalDot11bDot11gSupport => '1.3.6.1.4.1.14179.2.3.2.1.20',
      bsnGlobalDot11bDataRate6Mhz => '1.3.6.1.4.1.14179.2.3.2.1.21',
      bsnGlobalDot11bDataRate9Mhz => '1.3.6.1.4.1.14179.2.3.2.1.22',
      bsnGlobalDot11bDataRate12Mhz => '1.3.6.1.4.1.14179.2.3.2.1.23',
      bsnGlobalDot11bDataRate18Mhz => '1.3.6.1.4.1.14179.2.3.2.1.24',
      bsnGlobalDot11bDataRate24Mhz => '1.3.6.1.4.1.14179.2.3.2.1.25',
      bsnGlobalDot11bDataRate36Mhz => '1.3.6.1.4.1.14179.2.3.2.1.26',
      bsnGlobalDot11bDataRate48Mhz => '1.3.6.1.4.1.14179.2.3.2.1.27',
      bsnGlobalDot11bDataRate54Mhz => '1.3.6.1.4.1.14179.2.3.2.1.28',
      bsnGlobalDot11bPicoCellMode => '1.3.6.1.4.1.14179.2.3.2.1.29',
      bsnGlobalDot11bDynamicChannelAssignment => '1.3.6.1.4.1.14179.2.3.2.1.3',
      bsnGlobalDot11bFastRoamingMode => '1.3.6.1.4.1.14179.2.3.2.1.30',
      bsnGlobalDot11bFastRoamingVoipMinRate => '1.3.6.1.4.1.14179.2.3.2.1.31',
      bsnGlobalDot11bFastRoamingVoipPercentage => '1.3.6.1.4.1.14179.2.3.2.1.32',
      bsnGlobalDot11b80211eMaxBandwidth => '1.3.6.1.4.1.14179.2.3.2.1.33',
      bsnGlobalDot11bDTPCSupport => '1.3.6.1.4.1.14179.2.3.2.1.34',
      bsnGlobalDot11bCurrentChannel => '1.3.6.1.4.1.14179.2.3.2.1.4',
      bsnGlobalDot11bDynamicChannelUpdateInterval => '1.3.6.1.4.1.14179.2.3.2.1.5',
      bsnGlobalDot11bInputsForDCA => '1.3.6.1.4.1.14179.2.3.2.1.6',
      bsnGlobalDot11bChannelUpdateCmdInvoke => '1.3.6.1.4.1.14179.2.3.2.1.7',
      bsnGlobalDot11bChannelUpdateCmdStatus => '1.3.6.1.4.1.14179.2.3.2.1.8',
      bsnGlobalDot11bDynamicTransmitPowerControl => '1.3.6.1.4.1.14179.2.3.2.1.9',
      bsnGlobalDot11bPhy => '1.3.6.1.4.1.14179.2.3.2.2',
      bsnGlobalDot11bMediumOccupancyLimit => '1.3.6.1.4.1.14179.2.3.2.2.1',
      bsnGlobalDot11bNumberofChannels => '1.3.6.1.4.1.14179.2.3.2.2.10',
      bsnGlobalDot11bRTSThreshold => '1.3.6.1.4.1.14179.2.3.2.2.11',
      bsnGlobalDot11bShortRetryLimit => '1.3.6.1.4.1.14179.2.3.2.2.12',
      bsnGlobalDot11bLongRetryLimit => '1.3.6.1.4.1.14179.2.3.2.2.13',
      bsnGlobalDot11bFragmentationThreshold => '1.3.6.1.4.1.14179.2.3.2.2.14',
      bsnGlobalDot11bMaxTransmitMSDULifetime => '1.3.6.1.4.1.14179.2.3.2.2.15',
      bsnGlobalDot11bMaxReceiveLifetime => '1.3.6.1.4.1.14179.2.3.2.2.16',
      bsnGlobalDot11bEDThreshold => '1.3.6.1.4.1.14179.2.3.2.2.17',
      bsnGlobalDot11bChannelAgilityEnabled => '1.3.6.1.4.1.14179.2.3.2.2.18',
      bsnGlobalDot11bPBCCOptionImplemented => '1.3.6.1.4.1.14179.2.3.2.2.19',
      bsnGlobalDot11bCFPPeriod => '1.3.6.1.4.1.14179.2.3.2.2.2',
      bsnGlobalDot11bShortPreambleOptionImplemented => '1.3.6.1.4.1.14179.2.3.2.2.20',
      bsnGlobalDot11bCFPMaxDuration => '1.3.6.1.4.1.14179.2.3.2.2.3',
      bsnGlobalDot11bCFPollable => '1.3.6.1.4.1.14179.2.3.2.2.5',
      bsnGlobalDot11bCFPollRequest => '1.3.6.1.4.1.14179.2.3.2.2.6',
      bsnGlobalDot11bDTIMPeriod => '1.3.6.1.4.1.14179.2.3.2.2.7',
      bsnGlobalDot11bMaximumTransmitPowerLevel => '1.3.6.1.4.1.14179.2.3.2.2.8',
      bsnGlobalDot11bFirstChannelNumber => '1.3.6.1.4.1.14179.2.3.2.2.9',
      bsnGlobalDot11a => '1.3.6.1.4.1.14179.2.3.3',
      bsnGlobalDot11aConfig => '1.3.6.1.4.1.14179.2.3.3.1',
      bsnGlobalDot11aNetworkStatus => '1.3.6.1.4.1.14179.2.3.3.1.1',
      bsnGlobalDot11aChannelUpdateCmdInvoke => '1.3.6.1.4.1.14179.2.3.3.1.10',
      bsnGlobalDot11aChannelUpdateCmdStatus => '1.3.6.1.4.1.14179.2.3.3.1.11',
      bsnGlobalDot11aDynamicTransmitPowerControl => '1.3.6.1.4.1.14179.2.3.3.1.12',
      bsnGlobalDot11aCurrentTxPowerLevel => '1.3.6.1.4.1.14179.2.3.3.1.13',
      bsnGlobalDot11aDynamicTxPowerControlInterval => '1.3.6.1.4.1.14179.2.3.3.1.14',
      bsnGlobalDot11aInputsForDTP => '1.3.6.1.4.1.14179.2.3.3.1.15',
      bsnGlobalDot11aPowerUpdateCmdInvoke => '1.3.6.1.4.1.14179.2.3.3.1.16',
      bsnGlobalDot11aPowerUpdateCmdStatus => '1.3.6.1.4.1.14179.2.3.3.1.17',
      bsnGlobalDot11aDataRate6Mhz => '1.3.6.1.4.1.14179.2.3.3.1.19',
      bsnGlobalDot11aLowBandNetwork => '1.3.6.1.4.1.14179.2.3.3.1.2',
      bsnGlobalDot11aDataRate9Mhz => '1.3.6.1.4.1.14179.2.3.3.1.20',
      bsnGlobalDot11aDataRate12Mhz => '1.3.6.1.4.1.14179.2.3.3.1.21',
      bsnGlobalDot11aDataRate18Mhz => '1.3.6.1.4.1.14179.2.3.3.1.22',
      bsnGlobalDot11aDataRate24Mhz => '1.3.6.1.4.1.14179.2.3.3.1.23',
      bsnGlobalDot11aDataRate36Mhz => '1.3.6.1.4.1.14179.2.3.3.1.24',
      bsnGlobalDot11aDataRate48Mhz => '1.3.6.1.4.1.14179.2.3.3.1.25',
      bsnGlobalDot11aDataRate54Mhz => '1.3.6.1.4.1.14179.2.3.3.1.26',
      bsnGlobalDot11aPicoCellMode => '1.3.6.1.4.1.14179.2.3.3.1.27',
      bsnGlobalDot11aFastRoamingMode => '1.3.6.1.4.1.14179.2.3.3.1.28',
      bsnGlobalDot11aFastRoamingVoipMinRate => '1.3.6.1.4.1.14179.2.3.3.1.29',
      bsnGlobalDot11aMediumBandNetwork => '1.3.6.1.4.1.14179.2.3.3.1.3',
      bsnGlobalDot11aFastRoamingVoipPercentage => '1.3.6.1.4.1.14179.2.3.3.1.30',
      bsnGlobalDot11a80211eMaxBandwidth => '1.3.6.1.4.1.14179.2.3.3.1.31',
      bsnGlobalDot11aDTPCSupport => '1.3.6.1.4.1.14179.2.3.3.1.32',
      bsnGlobalDot11aHighBandNetwork => '1.3.6.1.4.1.14179.2.3.3.1.4',
      bsnGlobalDot11aBeaconPeriod => '1.3.6.1.4.1.14179.2.3.3.1.5',
      bsnGlobalDot11aDynamicChannelAssignment => '1.3.6.1.4.1.14179.2.3.3.1.6',
      bsnGlobalDot11aCurrentChannel => '1.3.6.1.4.1.14179.2.3.3.1.7',
      bsnGlobalDot11aDynamicChannelUpdateInterval => '1.3.6.1.4.1.14179.2.3.3.1.8',
      bsnGlobalDot11aInputsForDCA => '1.3.6.1.4.1.14179.2.3.3.1.9',
      bsnGlobalDot11aPhy => '1.3.6.1.4.1.14179.2.3.3.2',
      bsnGlobalDot11aMediumOccupancyLimit => '1.3.6.1.4.1.14179.2.3.3.2.1',
      bsnGlobalDot11aNumberofChannels => '1.3.6.1.4.1.14179.2.3.3.2.10',
      bsnGlobalDot11aRTSThreshold => '1.3.6.1.4.1.14179.2.3.3.2.11',
      bsnGlobalDot11aShortRetryLimit => '1.3.6.1.4.1.14179.2.3.3.2.12',
      bsnGlobalDot11aLongRetryLimit => '1.3.6.1.4.1.14179.2.3.3.2.13',
      bsnGlobalDot11aFragmentationThreshold => '1.3.6.1.4.1.14179.2.3.3.2.14',
      bsnGlobalDot11aMaxTransmitMSDULifetime => '1.3.6.1.4.1.14179.2.3.3.2.15',
      bsnGlobalDot11aMaxReceiveLifetime => '1.3.6.1.4.1.14179.2.3.3.2.16',
      bsnGlobalDot11aTIThreshold => '1.3.6.1.4.1.14179.2.3.3.2.17',
      bsnGlobalDot11aChannelAgilityEnabled => '1.3.6.1.4.1.14179.2.3.3.2.18',
      bsnGlobalDot11aCFPPeriod => '1.3.6.1.4.1.14179.2.3.3.2.2',
      bsnGlobalDot11aCFPMaxDuration => '1.3.6.1.4.1.14179.2.3.3.2.3',
      bsnGlobalDot11aCFPollable => '1.3.6.1.4.1.14179.2.3.3.2.5',
      bsnGlobalDot11aCFPollRequest => '1.3.6.1.4.1.14179.2.3.3.2.6',
      bsnGlobalDot11aDTIMPeriod => '1.3.6.1.4.1.14179.2.3.3.2.7',
      bsnGlobalDot11aMaximumTransmitPowerLevel => '1.3.6.1.4.1.14179.2.3.3.2.8',
      bsnGlobalDot11aFirstChannelNumber => '1.3.6.1.4.1.14179.2.3.3.2.9',
      bsnGlobalDot11h => '1.3.6.1.4.1.14179.2.3.4',
      bsnGlobalDot11hConfig => '1.3.6.1.4.1.14179.2.3.4.1',
      bsnGlobalDot11hPowerConstraint => '1.3.6.1.4.1.14179.2.3.4.1.1',
      bsnGlobalDot11hChannelSwitchEnable => '1.3.6.1.4.1.14179.2.3.4.1.2',
      bsnGlobalDot11hChannelSwitchMode => '1.3.6.1.4.1.14179.2.3.4.1.3',
      bsnRrm => '1.3.6.1.4.1.14179.2.4',
      bsnRrmDot11a => '1.3.6.1.4.1.14179.2.4.1',
      bsnRrmDot11aGroup => '1.3.6.1.4.1.14179.2.4.1.1',
      bsnRrmDot11aGlobalAutomaticGrouping => '1.3.6.1.4.1.14179.2.4.1.1.1',
      bsnRrmDot11aGroupLeaderMacAddr => '1.3.6.1.4.1.14179.2.4.1.1.2',
      bsnRrmIsDot11aGroupLeader => '1.3.6.1.4.1.14179.2.4.1.1.3',
      bsnRrmDot11aGroupLastUpdateTime => '1.3.6.1.4.1.14179.2.4.1.1.4',
      bsnRrmDot11aGlobalGroupInterval => '1.3.6.1.4.1.14179.2.4.1.1.5',
      bsnWrasDot11aGroupTable => '1.3.6.1.4.1.14179.2.4.1.1.9',
      bsnWrasDot11aGroupEntry => '1.3.6.1.4.1.14179.2.4.1.1.9.1',
      bsnWrasDot11aPeerMacAddress => '1.3.6.1.4.1.14179.2.4.1.1.9.1.1',
      bsnWrasDot11aPeerIpAddress => '1.3.6.1.4.1.14179.2.4.1.1.9.1.21',
      bsnRrmDot11aAPDefault => '1.3.6.1.4.1.14179.2.4.1.6',
      bsnRrmDot11aForeignInterferenceThreshold => '1.3.6.1.4.1.14179.2.4.1.6.1',
      bsnRrmDot11aNoiseMeasurementInterval => '1.3.6.1.4.1.14179.2.4.1.6.10',
      bsnRrmDot11aLoadMeasurementInterval => '1.3.6.1.4.1.14179.2.4.1.6.11',
      bsnRrmDot11aCoverageMeasurementInterval => '1.3.6.1.4.1.14179.2.4.1.6.12',
      bsnRrmDot11aChannelMonitorList => '1.3.6.1.4.1.14179.2.4.1.6.13',
      bsnRrmDot11aForeignNoiseThreshold => '1.3.6.1.4.1.14179.2.4.1.6.2',
      bsnRrmDot11aRFUtilizationThreshold => '1.3.6.1.4.1.14179.2.4.1.6.3',
      bsnRrmDot11aThroughputThreshold => '1.3.6.1.4.1.14179.2.4.1.6.4',
      bsnRrmDot11aMobilesThreshold => '1.3.6.1.4.1.14179.2.4.1.6.5',
      bsnRrmDot11aCoverageThreshold => '1.3.6.1.4.1.14179.2.4.1.6.6',
      bsnRrmDot11aMobileMinExceptionLevel => '1.3.6.1.4.1.14179.2.4.1.6.7',
      bsnRrmDot11aCoverageExceptionLevel => '1.3.6.1.4.1.14179.2.4.1.6.8',
      bsnRrmDot11aSignalMeasurementInterval => '1.3.6.1.4.1.14179.2.4.1.6.9',
      bsnRrmDot11aSetFactoryDefault => '1.3.6.1.4.1.14179.2.4.1.7',
      bsnRrmDot11b => '1.3.6.1.4.1.14179.2.4.2',
      bsnRrmDot11bGroup => '1.3.6.1.4.1.14179.2.4.2.1',
      bsnRrmDot11bGlobalAutomaticGrouping => '1.3.6.1.4.1.14179.2.4.2.1.1',
      bsnRrmDot11bGroupLeaderMacAddr => '1.3.6.1.4.1.14179.2.4.2.1.2',
      bsnRrmIsDot11bGroupLeader => '1.3.6.1.4.1.14179.2.4.2.1.3',
      bsnRrmDot11bGroupLastUpdateTime => '1.3.6.1.4.1.14179.2.4.2.1.4',
      bsnRrmDot11bGlobalGroupInterval => '1.3.6.1.4.1.14179.2.4.2.1.5',
      bsnWrasDot11bGroupTable => '1.3.6.1.4.1.14179.2.4.2.1.9',
      bsnWrasDot11bGroupEntry => '1.3.6.1.4.1.14179.2.4.2.1.9.1',
      bsnWrasDot11bPeerMacAddress => '1.3.6.1.4.1.14179.2.4.2.1.9.1.1',
      bsnWrasDot11bPeerIpAddress => '1.3.6.1.4.1.14179.2.4.2.1.9.1.21',
      bsnRrmDot11bAPDefault => '1.3.6.1.4.1.14179.2.4.2.6',
      bsnRrmDot11bForeignInterferenceThreshold => '1.3.6.1.4.1.14179.2.4.2.6.1',
      bsnRrmDot11bNoiseMeasurementInterval => '1.3.6.1.4.1.14179.2.4.2.6.10',
      bsnRrmDot11bLoadMeasurementInterval => '1.3.6.1.4.1.14179.2.4.2.6.11',
      bsnRrmDot11bCoverageMeasurementInterval => '1.3.6.1.4.1.14179.2.4.2.6.12',
      bsnRrmDot11bChannelMonitorList => '1.3.6.1.4.1.14179.2.4.2.6.13',
      bsnRrmDot11bForeignNoiseThreshold => '1.3.6.1.4.1.14179.2.4.2.6.2',
      bsnRrmDot11bRFUtilizationThreshold => '1.3.6.1.4.1.14179.2.4.2.6.3',
      bsnRrmDot11bThroughputThreshold => '1.3.6.1.4.1.14179.2.4.2.6.4',
      bsnRrmDot11bMobilesThreshold => '1.3.6.1.4.1.14179.2.4.2.6.5',
      bsnRrmDot11bCoverageThreshold => '1.3.6.1.4.1.14179.2.4.2.6.6',
      bsnRrmDot11bMobileMinExceptionLevel => '1.3.6.1.4.1.14179.2.4.2.6.7',
      bsnRrmDot11bCoverageExceptionLevel => '1.3.6.1.4.1.14179.2.4.2.6.8',
      bsnRrmDot11bSignalMeasurementInterval => '1.3.6.1.4.1.14179.2.4.2.6.9',
      bsnRrmDot11bSetFactoryDefault => '1.3.6.1.4.1.14179.2.4.2.7',
      bsnAAA => '1.3.6.1.4.1.14179.2.5',
      bsnRadiusAuthServerTable => '1.3.6.1.4.1.14179.2.5.1',
      bsnRadiusAuthServerEntry => '1.3.6.1.4.1.14179.2.5.1.1',
      bsnRadiusAuthServerIndex => '1.3.6.1.4.1.14179.2.5.1.1.1',
      bsnRadiusAuthServerIPSecEncryption => '1.3.6.1.4.1.14179.2.5.1.1.10',
      bsnRadiusAuthServerIPSecIKEPhase1 => '1.3.6.1.4.1.14179.2.5.1.1.11',
      bsnRadiusAuthServerIPSecIKELifetime => '1.3.6.1.4.1.14179.2.5.1.1.12',
      bsnRadiusAuthServerIPSecDHGroup => '1.3.6.1.4.1.14179.2.5.1.1.13',
      bsnRadiusAuthServerNetworkUserConfig => '1.3.6.1.4.1.14179.2.5.1.1.14',
      bsnRadiusAuthServerMgmtUserConfig => '1.3.6.1.4.1.14179.2.5.1.1.15',
      bsnRadiusAuthServerRetransmitTimeout => '1.3.6.1.4.1.14179.2.5.1.1.17',
      bsnRadiusAuthServerKeyWrapKEKkey => '1.3.6.1.4.1.14179.2.5.1.1.18',
      bsnRadiusAuthServerKeyWrapMACKkey => '1.3.6.1.4.1.14179.2.5.1.1.19',
      bsnRadiusAuthServerAddress => '1.3.6.1.4.1.14179.2.5.1.1.2',
      bsnRadiusAuthServerKeyWrapFormat => '1.3.6.1.4.1.14179.2.5.1.1.20',
      bsnRadiusAuthServerRowStatus => '1.3.6.1.4.1.14179.2.5.1.1.26',
      bsnRadiusAuthClientServerPortNumber => '1.3.6.1.4.1.14179.2.5.1.1.3',
      bsnRadiusAuthServerKey => '1.3.6.1.4.1.14179.2.5.1.1.4',
      bsnRadiusAuthServerStatus => '1.3.6.1.4.1.14179.2.5.1.1.5',
      bsnRadiusAuthServerKeyFormat => '1.3.6.1.4.1.14179.2.5.1.1.6',
      bsnRadiusAuthServerRFC3576 => '1.3.6.1.4.1.14179.2.5.1.1.7',
      bsnRadiusAuthServerIPSec => '1.3.6.1.4.1.14179.2.5.1.1.8',
      bsnRadiusAuthServerIPSecAuth => '1.3.6.1.4.1.14179.2.5.1.1.9',
      bsnLocalNetUserTable => '1.3.6.1.4.1.14179.2.5.10',
      bsnLocalNetUserEntry => '1.3.6.1.4.1.14179.2.5.10.1',
      bsnLocalNetUserName => '1.3.6.1.4.1.14179.2.5.10.1.1',
      bsnLocalNetUserWlanId => '1.3.6.1.4.1.14179.2.5.10.1.2',
      bsnLocalNetUserRowStatus => '1.3.6.1.4.1.14179.2.5.10.1.24',
      bsnLocalNetUserPassword => '1.3.6.1.4.1.14179.2.5.10.1.3',
      bsnLocalNetUserDescription => '1.3.6.1.4.1.14179.2.5.10.1.4',
      bsnLocalNetUserLifetime => '1.3.6.1.4.1.14179.2.5.10.1.5',
      bsnLocalNetUserStartTime => '1.3.6.1.4.1.14179.2.5.10.1.6',
      bsnLocalNetUserRemainingTime => '1.3.6.1.4.1.14179.2.5.10.1.7',
      bsnLocalManagementUserTable => '1.3.6.1.4.1.14179.2.5.11',
      bsnLocalManagementUserEntry => '1.3.6.1.4.1.14179.2.5.11.1',
      bsnLocalManagementUserName => '1.3.6.1.4.1.14179.2.5.11.1.1',
      bsnLocalManagementUserPassword => '1.3.6.1.4.1.14179.2.5.11.1.2',
      bsnLocalManagementUserRowStatus => '1.3.6.1.4.1.14179.2.5.11.1.23',
      bsnLocalManagementUserAccessMode => '1.3.6.1.4.1.14179.2.5.11.1.3',
      bsnRadiusAuthKeyWrapEnable => '1.3.6.1.4.1.14179.2.5.12',
      bsnRadiusAuthCacheCredentialsLocally => '1.3.6.1.4.1.14179.2.5.14',
      bsnAAAMacDelimiter => '1.3.6.1.4.1.14179.2.5.15',
      bsnAAARadiusCompatibilityMode => '1.3.6.1.4.1.14179.2.5.16',
      bsnAAARadiusCallStationIdType => '1.3.6.1.4.1.14179.2.5.17',
      bsnExternalPolicyServerAclName => '1.3.6.1.4.1.14179.2.5.18',
      bsnExternalPolicyServerTable => '1.3.6.1.4.1.14179.2.5.19',
      bsnExternalPolicyServerEntry => '1.3.6.1.4.1.14179.2.5.19.1',
      bsnExternalPolicyServerIndex => '1.3.6.1.4.1.14179.2.5.19.1.1',
      bsnExternalPolicyServerAddress => '1.3.6.1.4.1.14179.2.5.19.1.2',
      bsnExternalPolicyServerRowStatus => '1.3.6.1.4.1.14179.2.5.19.1.26',
      bsnExternalPolicyServerPortNumber => '1.3.6.1.4.1.14179.2.5.19.1.3',
      bsnExternalPolicyServerKey => '1.3.6.1.4.1.14179.2.5.19.1.4',
      bsnExternalPolicyServerAdminStatus => '1.3.6.1.4.1.14179.2.5.19.1.5',
      bsnExternalPolicyServerConnectionStatus => '1.3.6.1.4.1.14179.2.5.19.1.6',
      bsnRadiusAccServerTable => '1.3.6.1.4.1.14179.2.5.2',
      bsnRadiusAccServerEntry => '1.3.6.1.4.1.14179.2.5.2.1',
      bsnRadiusAccServerIndex => '1.3.6.1.4.1.14179.2.5.2.1.1',
      bsnRadiusAccServerIPSecIKEPhase1 => '1.3.6.1.4.1.14179.2.5.2.1.10',
      bsnRadiusAccServerIPSecIKELifetime => '1.3.6.1.4.1.14179.2.5.2.1.11',
      bsnRadiusAccServerIPSecDHGroup => '1.3.6.1.4.1.14179.2.5.2.1.12',
      bsnRadiusAccServerNetworkUserConfig => '1.3.6.1.4.1.14179.2.5.2.1.13',
      bsnRadiusAccServerRetransmitTimeout => '1.3.6.1.4.1.14179.2.5.2.1.14',
      bsnRadiusAccServerAddress => '1.3.6.1.4.1.14179.2.5.2.1.2',
      bsnRadiusAccServerRowStatus => '1.3.6.1.4.1.14179.2.5.2.1.26',
      bsnRadiusAccClientServerPortNumber => '1.3.6.1.4.1.14179.2.5.2.1.3',
      bsnRadiusAccServerKey => '1.3.6.1.4.1.14179.2.5.2.1.4',
      bsnRadiusAccServerStatus => '1.3.6.1.4.1.14179.2.5.2.1.5',
      bsnRadiusAccServerKeyFormat => '1.3.6.1.4.1.14179.2.5.2.1.6',
      bsnRadiusAccServerIPSec => '1.3.6.1.4.1.14179.2.5.2.1.7',
      bsnRadiusAccServerIPSecAuth => '1.3.6.1.4.1.14179.2.5.2.1.8',
      bsnRadiusAccServerIPSecEncryption => '1.3.6.1.4.1.14179.2.5.2.1.9',
      bsnAAALocalDatabaseSize => '1.3.6.1.4.1.14179.2.5.20',
      bsnAAACurrentLocalDatabaseSize => '1.3.6.1.4.1.14179.2.5.21',
      bsnAPAuthorizationTable => '1.3.6.1.4.1.14179.2.5.22',
      bsnAPAuthorizationEntry => '1.3.6.1.4.1.14179.2.5.22.1',
      bsnAPAuthMacAddress => '1.3.6.1.4.1.14179.2.5.22.1.1',
      bsnAPAuthCertificateType => '1.3.6.1.4.1.14179.2.5.22.1.2',
      bsnAPAuthRowStatus => '1.3.6.1.4.1.14179.2.5.22.1.20',
      bsnAPAuthHashKey => '1.3.6.1.4.1.14179.2.5.22.1.3',
      bsnRadiusAuthServerStatsTable => '1.3.6.1.4.1.14179.2.5.3',
      bsnRadiusAuthServerStatsEntry => '1.3.6.1.4.1.14179.2.5.3.1',
      bsnRadiusAuthClientAccessRejects => '1.3.6.1.4.1.14179.2.5.3.1.10',
      bsnRadiusAuthClientAccessChallenges => '1.3.6.1.4.1.14179.2.5.3.1.11',
      bsnRadiusAuthClientMalformedAccessResponses => '1.3.6.1.4.1.14179.2.5.3.1.12',
      bsnRadiusAuthClientBadAuthenticators => '1.3.6.1.4.1.14179.2.5.3.1.13',
      bsnRadiusAuthClientPendingRequests => '1.3.6.1.4.1.14179.2.5.3.1.14',
      bsnRadiusAuthClientTimeouts => '1.3.6.1.4.1.14179.2.5.3.1.15',
      bsnRadiusAuthClientUnknownTypes => '1.3.6.1.4.1.14179.2.5.3.1.16',
      bsnRadiusAuthClientPacketsDropped => '1.3.6.1.4.1.14179.2.5.3.1.36',
      bsnRadiusAuthClientRoundTripTime => '1.3.6.1.4.1.14179.2.5.3.1.6',
      bsnRadiusAuthClientAccessRequests => '1.3.6.1.4.1.14179.2.5.3.1.7',
      bsnRadiusAuthClientAccessRetransmissions => '1.3.6.1.4.1.14179.2.5.3.1.8',
      bsnRadiusAuthClientAccessAccepts => '1.3.6.1.4.1.14179.2.5.3.1.9',
      bsnRadiusAccServerStatsTable => '1.3.6.1.4.1.14179.2.5.4',
      bsnRadiusAccServerStatsEntry => '1.3.6.1.4.1.14179.2.5.4.1',
      bsnRadiusAccClientMalformedResponses => '1.3.6.1.4.1.14179.2.5.4.1.10',
      bsnRadiusAccClientBadAuthenticators => '1.3.6.1.4.1.14179.2.5.4.1.11',
      bsnRadiusAccClientPendingRequests => '1.3.6.1.4.1.14179.2.5.4.1.12',
      bsnRadiusAccClientTimeouts => '1.3.6.1.4.1.14179.2.5.4.1.13',
      bsnRadiusAccClientUnknownTypes => '1.3.6.1.4.1.14179.2.5.4.1.14',
      bsnRadiusAccClientPacketsDropped => '1.3.6.1.4.1.14179.2.5.4.1.34',
      bsnRadiusAccClientRoundTripTime => '1.3.6.1.4.1.14179.2.5.4.1.6',
      bsnRadiusAccClientRequests => '1.3.6.1.4.1.14179.2.5.4.1.7',
      bsnRadiusAccClientRetransmissions => '1.3.6.1.4.1.14179.2.5.4.1.8',
      bsnRadiusAccClientResponses => '1.3.6.1.4.1.14179.2.5.4.1.9',
      bsnUsersTable => '1.3.6.1.4.1.14179.2.5.5',
      bsnUsersEntry => '1.3.6.1.4.1.14179.2.5.5.1',
      bsnUserName => '1.3.6.1.4.1.14179.2.5.5.1.2',
      bsnUserRowStatus => '1.3.6.1.4.1.14179.2.5.5.1.26',
      bsnUserPassword => '1.3.6.1.4.1.14179.2.5.5.1.3',
      bsnUserEssIndex => '1.3.6.1.4.1.14179.2.5.5.1.4',
      bsnUserAccessMode => '1.3.6.1.4.1.14179.2.5.5.1.5',
      bsnUserType => '1.3.6.1.4.1.14179.2.5.5.1.6',
      bsnUserInterfaceName => '1.3.6.1.4.1.14179.2.5.5.1.7',
      bsnBlackListClientTable => '1.3.6.1.4.1.14179.2.5.6',
      bsnBlackListClientEntry => '1.3.6.1.4.1.14179.2.5.6.1',
      bsnBlackListClientMacAddress => '1.3.6.1.4.1.14179.2.5.6.1.1',
      bsnBlackListClientDescription => '1.3.6.1.4.1.14179.2.5.6.1.2',
      bsnBlackListClientRowStatus => '1.3.6.1.4.1.14179.2.5.6.1.22',
      bsnAclTable => '1.3.6.1.4.1.14179.2.5.7',
      bsnAclEntry => '1.3.6.1.4.1.14179.2.5.7.1',
      bsnAclName => '1.3.6.1.4.1.14179.2.5.7.1.1',
      bsnAclApplyMode => '1.3.6.1.4.1.14179.2.5.7.1.2',
      bsnAclRowStatus => '1.3.6.1.4.1.14179.2.5.7.1.20',
      bsnAclRuleTable => '1.3.6.1.4.1.14179.2.5.8',
      bsnAclRuleEntry => '1.3.6.1.4.1.14179.2.5.8.1',
      bsnAclRuleStartSourcePort => '1.3.6.1.4.1.14179.2.5.8.1.10',
      bsnAclRuleEndSourcePort => '1.3.6.1.4.1.14179.2.5.8.1.11',
      bsnAclRuleStartDestinationPort => '1.3.6.1.4.1.14179.2.5.8.1.12',
      bsnAclRuleEndDestinationPort => '1.3.6.1.4.1.14179.2.5.8.1.13',
      bsnAclRuleDscp => '1.3.6.1.4.1.14179.2.5.8.1.14',
      bsnAclNewRuleIndex => '1.3.6.1.4.1.14179.2.5.8.1.15',
      bsnAclRuleIndex => '1.3.6.1.4.1.14179.2.5.8.1.2',
      bsnAclRuleAction => '1.3.6.1.4.1.14179.2.5.8.1.3',
      bsnAclRuleDirection => '1.3.6.1.4.1.14179.2.5.8.1.4',
      bsnAclRuleRowStatus => '1.3.6.1.4.1.14179.2.5.8.1.40',
      bsnAclRuleSourceIpAddress => '1.3.6.1.4.1.14179.2.5.8.1.5',
      bsnAclRuleSourceIpNetmask => '1.3.6.1.4.1.14179.2.5.8.1.6',
      bsnAclRuleDestinationIpAddress => '1.3.6.1.4.1.14179.2.5.8.1.7',
      bsnAclRuleDestinationIpNetmask => '1.3.6.1.4.1.14179.2.5.8.1.8',
      bsnAclRuleProtocol => '1.3.6.1.4.1.14179.2.5.8.1.9',
      bsnMacFilterTable => '1.3.6.1.4.1.14179.2.5.9',
      bsnMacFilterEntry => '1.3.6.1.4.1.14179.2.5.9.1',
      bsnMacFilterAddress => '1.3.6.1.4.1.14179.2.5.9.1.1',
      bsnMacFilterWlanId => '1.3.6.1.4.1.14179.2.5.9.1.2',
      bsnMacFilterRowStatus => '1.3.6.1.4.1.14179.2.5.9.1.24',
      bsnMacFilterInterfaceName => '1.3.6.1.4.1.14179.2.5.9.1.3',
      bsnMacFilterDescription => '1.3.6.1.4.1.14179.2.5.9.1.4',
      bsnWrasGroups => '1.3.6.1.4.1.14179.2.50',
      bsnEssGroup => '1.3.6.1.4.1.14179.2.50.1',
      bsnWrasDepGroup => '1.3.6.1.4.1.14179.2.50.10',
      bsnWrasObsGroup => '1.3.6.1.4.1.14179.2.50.11',
      bsnWrasTrap => '1.3.6.1.4.1.14179.2.50.12',
      bsnEssGroupRev1 => '1.3.6.1.4.1.14179.2.50.13',
      bsnGlobalDot11GroupRev1 => '1.3.6.1.4.1.14179.2.50.14',
      bsnAAAGroupRev1 => '1.3.6.1.4.1.14179.2.50.15',
      bsnTrapsGroupRev1 => '1.3.6.1.4.1.14179.2.50.16',
      bsnWrasTrapRev1 => '1.3.6.1.4.1.14179.2.50.17',
      bsnApGroupRev1 => '1.3.6.1.4.1.14179.2.50.18',
      bsnUtilityGroupRev1 => '1.3.6.1.4.1.14179.2.50.19',
      bsnApGroup => '1.3.6.1.4.1.14179.2.50.2',
      bsnWrasObsGroupRev1 => '1.3.6.1.4.1.14179.2.50.20',
      bsnWrasObsTrap => '1.3.6.1.4.1.14179.2.50.21',
      bsnGlobalDot11Group => '1.3.6.1.4.1.14179.2.50.3',
      bsnRrmGroup => '1.3.6.1.4.1.14179.2.50.4',
      bsnAAAGroup => '1.3.6.1.4.1.14179.2.50.5',
      bsnTrapsGroup => '1.3.6.1.4.1.14179.2.50.6',
      bsnUtilityGroup => '1.3.6.1.4.1.14179.2.50.7',
      bsnMobilityGroup => '1.3.6.1.4.1.14179.2.50.8',
      bsnIpsecGroup => '1.3.6.1.4.1.14179.2.50.9',
      bsnWrasCompliances => '1.3.6.1.4.1.14179.2.51',
      bsnWrasCompliance => '1.3.6.1.4.1.14179.2.51.1',
      bsnWrasComplianceRev1 => '1.3.6.1.4.1.14179.2.51.2',
      bsnTrap => '1.3.6.1.4.1.14179.2.6',
      bsnTrapControl => '1.3.6.1.4.1.14179.2.6.1',
      bsnDot11StationTrapControlMask => '1.3.6.1.4.1.14179.2.6.1.1',
      bsn80211SecurityTrapControlMask => '1.3.6.1.4.1.14179.2.6.1.10',
      bsnWpsTrapControlEnable => '1.3.6.1.4.1.14179.2.6.1.11',
      bsnAPTrapControlMask => '1.3.6.1.4.1.14179.2.6.1.2',
      bsnAPProfileTrapControlMask => '1.3.6.1.4.1.14179.2.6.1.3',
      bsnAPParamUpdateTrapControlMask => '1.3.6.1.4.1.14179.2.6.1.4',
      bsnIpsecTrapsMask => '1.3.6.1.4.1.14179.2.6.1.5',
      bsnRogueAPTrapEnable => '1.3.6.1.4.1.14179.2.6.1.6',
      bsnRADIUSServerTrapEnable => '1.3.6.1.4.1.14179.2.6.1.7',
      bsnAuthenticationFailureTrapEnable => '1.3.6.1.4.1.14179.2.6.1.8',
      bsnConfigSaveTrapEnable => '1.3.6.1.4.1.14179.2.6.1.9',
      bsnTrapVariable => '1.3.6.1.4.1.14179.2.6.2',
      bsnAuthFailureUserName => '1.3.6.1.4.1.14179.2.6.2.1',
      bsnIkeTotalRespFailures => '1.3.6.1.4.1.14179.2.6.2.10',
      bsnNotifiesSent => '1.3.6.1.4.1.14179.2.6.2.11',
      bsnNotifiesReceived => '1.3.6.1.4.1.14179.2.6.2.12',
      bsnSuiteInitFailures => '1.3.6.1.4.1.14179.2.6.2.13',
      bsnSuiteRespondFailures => '1.3.6.1.4.1.14179.2.6.2.14',
      bsnInitiatorCookie => '1.3.6.1.4.1.14179.2.6.2.15',
      bsnResponderCookie => '1.3.6.1.4.1.14179.2.6.2.16',
      bsnIsakmpInvalidCookies => '1.3.6.1.4.1.14179.2.6.2.17',
      bsnCurrentRadiosCount => '1.3.6.1.4.1.14179.2.6.2.18',
      bsnLicenseRadioCount => '1.3.6.1.4.1.14179.2.6.2.19',
      bsnAuthFailureUserType => '1.3.6.1.4.1.14179.2.6.2.2',
      bsnAPMacAddrTrapVariable => '1.3.6.1.4.1.14179.2.6.2.20',
      bsnAPNameTrapVariable => '1.3.6.1.4.1.14179.2.6.2.21',
      bsnAPSlotIdTrapVariable => '1.3.6.1.4.1.14179.2.6.2.22',
      bsnAPChannelNumberTrapVariable => '1.3.6.1.4.1.14179.2.6.2.23',
      bsnAPCoverageThresholdTrapVariable => '1.3.6.1.4.1.14179.2.6.2.24',
      bsnAPCoverageFailedClients => '1.3.6.1.4.1.14179.2.6.2.25',
      bsnAPCoverageTotalClients => '1.3.6.1.4.1.14179.2.6.2.26',
      bsnClientMacAddr => '1.3.6.1.4.1.14179.2.6.2.27',
      bsnClientRssi => '1.3.6.1.4.1.14179.2.6.2.28',
      bsnClientSnr => '1.3.6.1.4.1.14179.2.6.2.29',
      bsnRemoteIPv4Address => '1.3.6.1.4.1.14179.2.6.2.3',
      bsnInterferenceEnergyBeforeChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.30',
      bsnInterferenceEnergyAfterChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.31',
      bsnAPPortNumberTrapVariable => '1.3.6.1.4.1.14179.2.6.2.32',
      bsnMaxRogueCount => '1.3.6.1.4.1.14179.2.6.2.33',
      bsnStationMacAddress => '1.3.6.1.4.1.14179.2.6.2.34',
      bsnStationAPMacAddr => '1.3.6.1.4.1.14179.2.6.2.35',
      bsnStationAPIfSlotId => '1.3.6.1.4.1.14179.2.6.2.36',
      bsnStationReasonCode => '1.3.6.1.4.1.14179.2.6.2.37',
      bsnStationBlacklistingReasonCode => '1.3.6.1.4.1.14179.2.6.2.38',
      bsnStationUserName => '1.3.6.1.4.1.14179.2.6.2.39',
      bsnIpsecErrorCount => '1.3.6.1.4.1.14179.2.6.2.4',
      bsnRogueAPOnWiredNetwork => '1.3.6.1.4.1.14179.2.6.2.40',
      bsnNavDosAttackSourceMacAddr => '1.3.6.1.4.1.14179.2.6.2.41',
      bsnWlanIdTrapVariable => '1.3.6.1.4.1.14179.2.6.2.42',
      bsnUserIpAddress => '1.3.6.1.4.1.14179.2.6.2.43',
      bsnRogueAdhocMode => '1.3.6.1.4.1.14179.2.6.2.44',
      bsnClearTrapVariable => '1.3.6.1.4.1.14179.2.6.2.45',
      bsnDuplicateIpTrapVariable => '1.3.6.1.4.1.14179.2.6.2.46',
      bsnDuplicateIpTrapClear => '1.3.6.1.4.1.14179.2.6.2.47',
      bsnDuplicateIpReportedByAP => '1.3.6.1.4.1.14179.2.6.2.48',
      bsnTrustedApRadioPolicyRequired => '1.3.6.1.4.1.14179.2.6.2.49',
      bsnIpsecSPI => '1.3.6.1.4.1.14179.2.6.2.5',
      bsnTrustedApEncryptionUsed => '1.3.6.1.4.1.14179.2.6.2.50',
      bsnTrustedApEncryptionRequired => '1.3.6.1.4.1.14179.2.6.2.51',
      bsnTrustedApRadioPolicyUsed => '1.3.6.1.4.1.14179.2.6.2.52',
      bsnNetworkType => '1.3.6.1.4.1.14179.2.6.2.53',
      bsnNetworkState => '1.3.6.1.4.1.14179.2.6.2.54',
      bsnSignatureType => '1.3.6.1.4.1.14179.2.6.2.55',
      bsnSignatureName => '1.3.6.1.4.1.14179.2.6.2.56',
      bsnSignatureDescription => '1.3.6.1.4.1.14179.2.6.2.57',
      bsnImpersonatedAPMacAddr => '1.3.6.1.4.1.14179.2.6.2.58',
      bsnTrustedApPreambleUsed => '1.3.6.1.4.1.14179.2.6.2.59',
      bsnRemoteUdpPort => '1.3.6.1.4.1.14179.2.6.2.6',
      bsnTrustedApPreambleRequired => '1.3.6.1.4.1.14179.2.6.2.60',
      bsnSignatureAttackPreced => '1.3.6.1.4.1.14179.2.6.2.61',
      bsnSignatureAttackFrequency => '1.3.6.1.4.1.14179.2.6.2.62',
      bsnSignatureAttackChannel => '1.3.6.1.4.1.14179.2.6.2.63',
      bsnSignatureAttackerMacAddress => '1.3.6.1.4.1.14179.2.6.2.64',
      bsnLicenseKeyTrapVariable => '1.3.6.1.4.1.14179.2.6.2.65',
      bsnApFunctionalityDisableReasonCode => '1.3.6.1.4.1.14179.2.6.2.66',
      bsnLicenseKeyFeatureSetTrapVariable => '1.3.6.1.4.1.14179.2.6.2.67',
      bsnApRegulatoryDomain => '1.3.6.1.4.1.14179.2.6.2.68',
      bsnAPAuthorizationFailureCause => '1.3.6.1.4.1.14179.2.6.2.69',
      bsnIkeAuthMethod => '1.3.6.1.4.1.14179.2.6.2.7',
      bsnAPIfUpDownCause => '1.3.6.1.4.1.14179.2.6.2.70',
      bsnAPInvalidRadioType => '1.3.6.1.4.1.14179.2.6.2.71',
      locationNotifyContent => '1.3.6.1.4.1.14179.2.6.2.72',
      bsnSignatureMacInfo => '1.3.6.1.4.1.14179.2.6.2.73',
      bsnImpersonatingSourceMacAddr => '1.3.6.1.4.1.14179.2.6.2.74',
      bsnIkeTotalInitFailures => '1.3.6.1.4.1.14179.2.6.2.8',
      bsnAPPreviousChannelNumberTrapVariable => '1.3.6.1.4.1.14179.2.6.2.83',
      bsnAPReasonCodeTrapVariable => '1.3.6.1.4.1.14179.2.6.2.84',
      bsnNoiseBeforeChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.85',
      bsnNoiseAfterChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.86',
      bsnInterferenceBeforeChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.87',
      bsnInterferenceAfterChannelUpdate => '1.3.6.1.4.1.14179.2.6.2.88',
      bsnIkeTotalInitNoResponses => '1.3.6.1.4.1.14179.2.6.2.9',
      bsnTraps => '1.3.6.1.4.1.14179.2.6.3',
      bsnDot11StationDisassociate => '1.3.6.1.4.1.14179.2.6.3.1',
      bsnAPIfDown => '1.3.6.1.4.1.14179.2.6.3.10',
      bsnAPLoadProfileFailed => '1.3.6.1.4.1.14179.2.6.3.11',
      bsnAPNoiseProfileFailed => '1.3.6.1.4.1.14179.2.6.3.12',
      bsnAPInterferenceProfileFailed => '1.3.6.1.4.1.14179.2.6.3.13',
      bsnAPCoverageProfileFailed => '1.3.6.1.4.1.14179.2.6.3.14',
      bsnAPCurrentTxPowerChanged => '1.3.6.1.4.1.14179.2.6.3.15',
      bsnAPCurrentChannelChanged => '1.3.6.1.4.1.14179.2.6.3.16',
      bsnDot11StationDeauthenticate => '1.3.6.1.4.1.14179.2.6.3.2',
      bsnRrmDot11aGroupingDone => '1.3.6.1.4.1.14179.2.6.3.21',
      bsnRrmDot11bGroupingDone => '1.3.6.1.4.1.14179.2.6.3.22',
      bsnConfigSaved => '1.3.6.1.4.1.14179.2.6.3.23',
      bsnDot11EssCreated => '1.3.6.1.4.1.14179.2.6.3.24',
      bsnDot11EssDeleted => '1.3.6.1.4.1.14179.2.6.3.25',
      bsnRADIUSServerNotResponding => '1.3.6.1.4.1.14179.2.6.3.26',
      bsnAuthenticationFailure => '1.3.6.1.4.1.14179.2.6.3.27',
      bsnIpsecEspAuthFailureTrap => '1.3.6.1.4.1.14179.2.6.3.28',
      bsnIpsecEspReplayFailureTrap => '1.3.6.1.4.1.14179.2.6.3.29',
      bsnDot11StationAuthenticateFail => '1.3.6.1.4.1.14179.2.6.3.3',
      bsnIpsecEspInvalidSpiTrap => '1.3.6.1.4.1.14179.2.6.3.31',
      bsnIpsecIkeNegFailure => '1.3.6.1.4.1.14179.2.6.3.33',
      bsnIpsecSuiteNegFailure => '1.3.6.1.4.1.14179.2.6.3.34',
      bsnIpsecInvalidCookieTrap => '1.3.6.1.4.1.14179.2.6.3.35',
      bsnRogueAPDetected => '1.3.6.1.4.1.14179.2.6.3.36',
      bsnAPLoadProfileUpdatedToPass => '1.3.6.1.4.1.14179.2.6.3.37',
      bsnAPNoiseProfileUpdatedToPass => '1.3.6.1.4.1.14179.2.6.3.38',
      bsnAPInterferenceProfileUpdatedToPass => '1.3.6.1.4.1.14179.2.6.3.39',
      bsnDot11StationAssociateFail => '1.3.6.1.4.1.14179.2.6.3.4',
      bsnAPCoverageProfileUpdatedToPass => '1.3.6.1.4.1.14179.2.6.3.40',
      bsnRogueAPRemoved => '1.3.6.1.4.1.14179.2.6.3.41',
      bsnRadiosExceedLicenseCount => '1.3.6.1.4.1.14179.2.6.3.42',
      bsnSensedTemperatureTooHigh => '1.3.6.1.4.1.14179.2.6.3.43',
      bsnSensedTemperatureTooLow => '1.3.6.1.4.1.14179.2.6.3.44',
      bsnTemperatureSensorFailure => '1.3.6.1.4.1.14179.2.6.3.45',
      bsnTemperatureSensorClear => '1.3.6.1.4.1.14179.2.6.3.46',
      bsnPOEControllerFailure => '1.3.6.1.4.1.14179.2.6.3.47',
      bsnMaxRogueCountExceeded => '1.3.6.1.4.1.14179.2.6.3.48',
      bsnMaxRogueCountClear => '1.3.6.1.4.1.14179.2.6.3.49',
      bsnAPUp => '1.3.6.1.4.1.14179.2.6.3.5',
      bsnApMaxRogueCountExceeded => '1.3.6.1.4.1.14179.2.6.3.50',
      bsnApMaxRogueCountClear => '1.3.6.1.4.1.14179.2.6.3.51',
      bsnDot11StationBlacklisted => '1.3.6.1.4.1.14179.2.6.3.52',
      bsnDot11StationAssociate => '1.3.6.1.4.1.14179.2.6.3.53',
      bsnApBigNavDosAttack => '1.3.6.1.4.1.14179.2.6.3.55',
      bsnTooManyUnsuccessLoginAttempts => '1.3.6.1.4.1.14179.2.6.3.56',
      bsnWepKeyDecryptError => '1.3.6.1.4.1.14179.2.6.3.57',
      bsnWpaMicErrorCounterActivated => '1.3.6.1.4.1.14179.2.6.3.58',
      bsnRogueAPDetectedOnWiredNetwork => '1.3.6.1.4.1.14179.2.6.3.59',
      bsnAPDown => '1.3.6.1.4.1.14179.2.6.3.6',
      bsnApHasNoRadioCards => '1.3.6.1.4.1.14179.2.6.3.60',
      bsnDuplicateIpAddressReported => '1.3.6.1.4.1.14179.2.6.3.61',
      bsnAPContainedAsARogue => '1.3.6.1.4.1.14179.2.6.3.62',
      bsnTrustedApHasInvalidSsid => '1.3.6.1.4.1.14179.2.6.3.63',
      bsnTrustedApIsMissing => '1.3.6.1.4.1.14179.2.6.3.64',
      bsnAdhocRogueAutoContained => '1.3.6.1.4.1.14179.2.6.3.65',
      bsnRogueApAutoContained => '1.3.6.1.4.1.14179.2.6.3.66',
      bsnTrustedApHasInvalidEncryption => '1.3.6.1.4.1.14179.2.6.3.67',
      bsnTrustedApHasInvalidRadioPolicy => '1.3.6.1.4.1.14179.2.6.3.68',
      bsnNetworkStateChanged => '1.3.6.1.4.1.14179.2.6.3.69',
      bsnAPAssociated => '1.3.6.1.4.1.14179.2.6.3.7',
      bsnSignatureAttackDetected => '1.3.6.1.4.1.14179.2.6.3.70',
      bsnAPRadioCardTxFailure => '1.3.6.1.4.1.14179.2.6.3.71',
      bsnAPRadioCardTxFailureClear => '1.3.6.1.4.1.14179.2.6.3.72',
      bsnAPRadioCardRxFailure => '1.3.6.1.4.1.14179.2.6.3.73',
      bsnAPRadioCardRxFailureClear => '1.3.6.1.4.1.14179.2.6.3.74',
      bsnAPImpersonationDetected => '1.3.6.1.4.1.14179.2.6.3.75',
      bsnTrustedApHasInvalidPreamble => '1.3.6.1.4.1.14179.2.6.3.76',
      bsnAPIPAddressFallback => '1.3.6.1.4.1.14179.2.6.3.77',
      bsnAPFunctionalityDisabled => '1.3.6.1.4.1.14179.2.6.3.78',
      bsnAPRegulatoryDomainMismatch => '1.3.6.1.4.1.14179.2.6.3.79',
      bsnAPDisassociated => '1.3.6.1.4.1.14179.2.6.3.8',
      bsnRxMulticastQueueFull => '1.3.6.1.4.1.14179.2.6.3.80',
      bsnRadarChannelDetected => '1.3.6.1.4.1.14179.2.6.3.81',
      bsnRadarChannelCleared => '1.3.6.1.4.1.14179.2.6.3.82',
      bsnAPAuthorizationFailure => '1.3.6.1.4.1.14179.2.6.3.83',
      radioCoreDumpTrap => '1.3.6.1.4.1.14179.2.6.3.84',
      invalidRadioTrap => '1.3.6.1.4.1.14179.2.6.3.85',
      countryChangeTrap => '1.3.6.1.4.1.14179.2.6.3.86',
      unsupportedAPTrap => '1.3.6.1.4.1.14179.2.6.3.87',
      heartbeatLossTrap => '1.3.6.1.4.1.14179.2.6.3.88',
      locationNotifyTrap => '1.3.6.1.4.1.14179.2.6.3.89',
      bsnAPIfUp => '1.3.6.1.4.1.14179.2.6.3.9',
      bsnUtility => '1.3.6.1.4.1.14179.2.7',
      bsnSyslog => '1.3.6.1.4.1.14179.2.7.1',
      bsnSyslogEnable => '1.3.6.1.4.1.14179.2.7.1.1',
      bsnSyslogRemoteAddress => '1.3.6.1.4.1.14179.2.7.1.2',
      bsnPing => '1.3.6.1.4.1.14179.2.7.2',
      bsnPingTestTable => '1.3.6.1.4.1.14179.2.7.2.1',
      bsnPingTestEntry => '1.3.6.1.4.1.14179.2.7.2.1.1',
      bsnPingTestId => '1.3.6.1.4.1.14179.2.7.2.1.1.1',
      bsnPingTestIPAddress => '1.3.6.1.4.1.14179.2.7.2.1.1.2',
      bsnPingTestRowStatus => '1.3.6.1.4.1.14179.2.7.2.1.1.25',
      bsnPingTestSendCount => '1.3.6.1.4.1.14179.2.7.2.1.1.3',
      bsnPingTestReceivedCount => '1.3.6.1.4.1.14179.2.7.2.1.1.4',
      bsnPingTestStatus => '1.3.6.1.4.1.14179.2.7.2.1.1.5',
      bsnPingTestMaxTimeInterval => '1.3.6.1.4.1.14179.2.7.2.1.1.6',
      bsnPingTestMinTimeInterval => '1.3.6.1.4.1.14179.2.7.2.1.1.7',
      bsnPingTestAvgTimeInterval => '1.3.6.1.4.1.14179.2.7.2.1.1.8',
      bsnLinkTest => '1.3.6.1.4.1.14179.2.7.3',
      bsnLinkTestTable => '1.3.6.1.4.1.14179.2.7.3.1',
      bsnLinkTestEntry => '1.3.6.1.4.1.14179.2.7.3.1.1',
      bsnLinkTestId => '1.3.6.1.4.1.14179.2.7.3.1.1.1',
      bsnLinkTestMacAddress => '1.3.6.1.4.1.14179.2.7.3.1.1.2',
      bsnLinkTestSendPktCount => '1.3.6.1.4.1.14179.2.7.3.1.1.3',
      bsnLinkTestRowStatus => '1.3.6.1.4.1.14179.2.7.3.1.1.30',
      bsnLinkTestSendPktLength => '1.3.6.1.4.1.14179.2.7.3.1.1.4',
      bsnLinkTestReceivedPktCount => '1.3.6.1.4.1.14179.2.7.3.1.1.5',
      bsnLinkTestClientRSSI => '1.3.6.1.4.1.14179.2.7.3.1.1.6',
      bsnLinkTestLocalSNR => '1.3.6.1.4.1.14179.2.7.3.1.1.7',
      bsnLinkTestLocalRSSI => '1.3.6.1.4.1.14179.2.7.3.1.1.8',
      bsnLinkTestStatus => '1.3.6.1.4.1.14179.2.7.3.1.1.9',
      bsnMobility => '1.3.6.1.4.1.14179.2.8',
      bsnMobilityConfig => '1.3.6.1.4.1.14179.2.8.1',
      bsnMobilityProtocolPortNum => '1.3.6.1.4.1.14179.2.8.1.1',
      bsnMobilityGroupMembersTable => '1.3.6.1.4.1.14179.2.8.1.10',
      bsnMobilityGroupMembersEntry => '1.3.6.1.4.1.14179.2.8.1.10.1',
      bsnMobilityGroupMemberMacAddress => '1.3.6.1.4.1.14179.2.8.1.10.1.1',
      bsnMobilityGroupMemberIPAddress => '1.3.6.1.4.1.14179.2.8.1.10.1.2',
      bsnMobilityGroupMemberRowStatus => '1.3.6.1.4.1.14179.2.8.1.10.1.22',
      bsnMobilityGroupMemberGroupName => '1.3.6.1.4.1.14179.2.8.1.10.1.3',
      bsnMobilityAnchorsTable => '1.3.6.1.4.1.14179.2.8.1.11',
      bsnMobilityAnchorsEntry => '1.3.6.1.4.1.14179.2.8.1.11.1',
      bsnMobilityAnchorWlanSsid => '1.3.6.1.4.1.14179.2.8.1.11.1.1',
      bsnMobilityAnchorSwitchIPAddress => '1.3.6.1.4.1.14179.2.8.1.11.1.2',
      bsnMobilityAnchorRowStatus => '1.3.6.1.4.1.14179.2.8.1.11.1.20',
      bsnMobilityDynamicDiscovery => '1.3.6.1.4.1.14179.2.8.1.3',
      bsnMobilityStatsReset => '1.3.6.1.4.1.14179.2.8.1.4',
      bsnMobilityStats => '1.3.6.1.4.1.14179.2.8.2',
      bsnTotalHandoffRequests => '1.3.6.1.4.1.14179.2.8.2.1',
      bsnTotalReceiveErrors => '1.3.6.1.4.1.14179.2.8.2.10',
      bsnTotalTransmitErrors => '1.3.6.1.4.1.14179.2.8.2.11',
      bsnTotalResponsesRetransmitted => '1.3.6.1.4.1.14179.2.8.2.12',
      bsnTotalHandoffEndRequestsReceived => '1.3.6.1.4.1.14179.2.8.2.13',
      bsnTotalStateTransitionsDisallowed => '1.3.6.1.4.1.14179.2.8.2.14',
      bsnTotalResourceErrors => '1.3.6.1.4.1.14179.2.8.2.15',
      bsnTotalHandoffRequestsSent => '1.3.6.1.4.1.14179.2.8.2.16',
      bsnTotalHandoffRepliesReceived => '1.3.6.1.4.1.14179.2.8.2.17',
      bsnTotalHandoffAsLocalReceived => '1.3.6.1.4.1.14179.2.8.2.18',
      bsnTotalHandoffAsForeignReceived => '1.3.6.1.4.1.14179.2.8.2.19',
      bsnTotalHandoffs => '1.3.6.1.4.1.14179.2.8.2.2',
      bsnTotalHandoffDeniesReceived => '1.3.6.1.4.1.14179.2.8.2.20',
      bsnTotalAnchorRequestsSent => '1.3.6.1.4.1.14179.2.8.2.21',
      bsnTotalAnchorDenyReceived => '1.3.6.1.4.1.14179.2.8.2.22',
      bsnTotalAnchorGrantReceived => '1.3.6.1.4.1.14179.2.8.2.23',
      bsnTotalAnchorTransferReceived => '1.3.6.1.4.1.14179.2.8.2.24',
      bsnTotalHandoffRequestsIgnored => '1.3.6.1.4.1.14179.2.8.2.25',
      bsnTotalPingPongHandoffRequestsDropped => '1.3.6.1.4.1.14179.2.8.2.26',
      bsnTotalHandoffRequestsDropped => '1.3.6.1.4.1.14179.2.8.2.27',
      bsnTotalHandoffRequestsDenied => '1.3.6.1.4.1.14179.2.8.2.28',
      bsnTotalClientHandoffAsLocal => '1.3.6.1.4.1.14179.2.8.2.29',
      bsnCurrentExportedClients => '1.3.6.1.4.1.14179.2.8.2.3',
      bsnTotalClientHandoffAsForeign => '1.3.6.1.4.1.14179.2.8.2.30',
      bsnTotalAnchorRequestsReceived => '1.3.6.1.4.1.14179.2.8.2.31',
      bsnTotalAnchorRequestsDenied => '1.3.6.1.4.1.14179.2.8.2.32',
      bsnTotalAnchorRequestsGranted => '1.3.6.1.4.1.14179.2.8.2.33',
      bsnTotalAnchorTransferred => '1.3.6.1.4.1.14179.2.8.2.34',
      bsnTotalHandoffRequestsReceived => '1.3.6.1.4.1.14179.2.8.2.35',
      bsnTotalExportedClients => '1.3.6.1.4.1.14179.2.8.2.4',
      bsnCurrentImportedClients => '1.3.6.1.4.1.14179.2.8.2.5',
      bsnTotalImportedClients => '1.3.6.1.4.1.14179.2.8.2.6',
      bsnTotalHandoffErrors => '1.3.6.1.4.1.14179.2.8.2.7',
      bsnTotalCommunicationErrors => '1.3.6.1.4.1.14179.2.8.2.8',
      bsnMobilityGroupDirectoryTable => '1.3.6.1.4.1.14179.2.8.2.9',
      bsnMobilityGroupDirectoryEntry => '1.3.6.1.4.1.14179.2.8.2.9.1',
      bsnGroupDirectoryMemberIPAddress => '1.3.6.1.4.1.14179.2.8.2.9.1.1',
      bsnMemberTotalHandoffErrors => '1.3.6.1.4.1.14179.2.8.2.9.1.10',
      bsnGroupDirectoryMemberMacAddress => '1.3.6.1.4.1.14179.2.8.2.9.1.2',
      bsnGroupDirectoryDicoveryType => '1.3.6.1.4.1.14179.2.8.2.9.1.3',
      bsnMemberTotalCommunicationErrors => '1.3.6.1.4.1.14179.2.8.2.9.1.30',
      bsnMemberCurrentAnchoredClients => '1.3.6.1.4.1.14179.2.8.2.9.1.4',
      bsnMemberTotalAnchoredClients => '1.3.6.1.4.1.14179.2.8.2.9.1.5',
      bsnMemberCurrentExportedClients => '1.3.6.1.4.1.14179.2.8.2.9.1.6',
      bsnMemberTotalExportedClients => '1.3.6.1.4.1.14179.2.8.2.9.1.7',
      bsnMemberCurrentImportedClients => '1.3.6.1.4.1.14179.2.8.2.9.1.8',
      bsnMemberTotalImportedClients => '1.3.6.1.4.1.14179.2.8.2.9.1.9',
      bsnIpsec => '1.3.6.1.4.1.14179.2.9',
      bsnWrasIpsecCACertificate => '1.3.6.1.4.1.14179.2.9.1',
      bsnWrasIpsecCACertificateUpdate => '1.3.6.1.4.1.14179.2.9.2',
      bsnWrasIpsecCertTable => '1.3.6.1.4.1.14179.2.9.3',
      bsnWrasIpsecCertEntry => '1.3.6.1.4.1.14179.2.9.3.1',
      bsnWrasIpsecCertName => '1.3.6.1.4.1.14179.2.9.3.1.1',
      bsnWrasIpsecCertificateUpdate => '1.3.6.1.4.1.14179.2.9.3.1.2',
      bsnWrasIpsecCertStatus => '1.3.6.1.4.1.14179.2.9.3.1.24',
      bsnWrasIpsecCertificate => '1.3.6.1.4.1.14179.2.9.3.1.3',
      bsnWrasIpsecCertPassword => '1.3.6.1.4.1.14179.2.9.3.1.4',
  },
  'ASYNCOS-MAIL-MIB' => {
      asyncOSMailObjects => '1.3.6.1.4.1.15497.1.1.1',
      perCentMemoryUtilization => '1.3.6.1.4.1.15497.1.1.1.1.0',
      perCentCPUUtilization => '1.3.6.1.4.1.15497.1.1.1.2.0',
      perCentDiskIOUtilization => '1.3.6.1.4.1.15497.1.1.1.3.0',
      perCentQueueUtilization => '1.3.6.1.4.1.15497.1.1.1.4.0',
      queueAvailabilityStatus => '1.3.6.1.4.1.15497.1.1.1.5.0',
      queueAvailabilityStatusDefinition => {
        1 => 'queueSpaceAvailable',
        2 => 'queueSpaceShortage',
        3 => 'queueFull',
      },
      resourceConservationReason => '1.3.6.1.4.1.15497.1.1.1.6.0',
      memoryAvailabilityStatus => '1.3.6.1.4.1.15497.1.1.1.7.0',
      memoryAvailabilityStatusDefinition => {
        1 => 'memoryAvailable',
        2 => 'memoryShortage',
        3 => 'memoryFull',
      },
      powerSupplyTable => '1.3.6.1.4.1.15497.1.1.1.8',
      powerSupplyEntry => '1.3.6.1.4.1.15497.1.1.1.8.1',
      powerSupplyIndex => '1.3.6.1.4.1.15497.1.1.1.8.1.1',
      powerSupplyStatus => '1.3.6.1.4.1.15497.1.1.1.8.1.2',
      powerSupplyStatusDefinition => {
        1 => 'powerSupplyNotInstalled',
        2 => 'powerSupplyHealthy',
        3 => 'powerSupplyNoAC',
        4 => 'powerSupplyFaulty',
      },
      powerSupplyRedundancy => '1.3.6.1.4.1.15497.1.1.1.8.1.3',
      powerSupplyName => '1.3.6.1.4.1.15497.1.1.1.8.1.4',
      temperatureTable => '1.3.6.1.4.1.15497.1.1.1.9',
      temperatureEntry => '1.3.6.1.4.1.15497.1.1.1.9.1',
      temperatureIndex => '1.3.6.1.4.1.15497.1.1.1.9.1.1',
      degreesCelsius => '1.3.6.1.4.1.15497.1.1.1.9.1.2',
      temperatureName => '1.3.6.1.4.1.15497.1.1.1.9.1.3',
      fanTable => '1.3.6.1.4.1.15497.1.1.1.10',
      fanEntry => '1.3.6.1.4.1.15497.1.1.1.10.1',
      fanIndex => '1.3.6.1.4.1.15497.1.1.1.10.1.1',
      fanRPMs => '1.3.6.1.4.1.15497.1.1.1.10.1.2',
      fanName => '1.3.6.1.4.1.15497.1.1.1.10.1.3',
      workQueueMessages => '1.3.6.1.4.1.15497.1.1.1.11.0',
      keyExpirationTable => '1.3.6.1.4.1.15497.1.1.1.12',
      keyExpirationEntry => '1.3.6.1.4.1.15497.1.1.1.12.1',
      keyExpirationIndex => '1.3.6.1.4.1.15497.1.1.1.12.1.1',
      keyDescription => '1.3.6.1.4.1.15497.1.1.1.12.1.2',
      keyIsPerpetual => '1.3.6.1.4.1.15497.1.1.1.12.1.3',
      keyIsPerpetualDefinition => 'SNMPv2-TC-v1::TruthValue',
      keySecondsUntilExpire => '1.3.6.1.4.1.15497.1.1.1.12.1.4',
      updateTable => '1.3.6.1.4.1.15497.1.1.1.13',
      updateEntry => '1.3.6.1.4.1.15497.1.1.1.13.1',
      updateIndex => '1.3.6.1.4.1.15497.1.1.1.13.1.1',
      updateServiceName => '1.3.6.1.4.1.15497.1.1.1.13.1.2',
      updates => '1.3.6.1.4.1.15497.1.1.1.13.1.3',
      updateFailures => '1.3.6.1.4.1.15497.1.1.1.13.1.4',
      oldestMessageAge => '1.3.6.1.4.1.15497.1.1.1.14.0',
      outstandingDNSRequests => '1.3.6.1.4.1.15497.1.1.1.15.0',
      pendingDNSRequests => '1.3.6.1.4.1.15497.1.1.1.16.0',
      raidEvents => '1.3.6.1.4.1.15497.1.1.1.17.0',
      raidTable => '1.3.6.1.4.1.15497.1.1.1.18',
      raidEntry => '1.3.6.1.4.1.15497.1.1.1.18.1',
      raidIndex => '1.3.6.1.4.1.15497.1.1.1.18.1.1',
      raidStatus => '1.3.6.1.4.1.15497.1.1.1.18.1.2',
      raidStatusDefinition => {
        1 => 'driveHealthy',
        2 => 'driveFailure',
        3 => 'driveRebuild',
      },
      raidID => '1.3.6.1.4.1.15497.1.1.1.18.1.3',
      raidLastError => '1.3.6.1.4.1.15497.1.1.1.18.1.4',
      openFilesOrSockets => '1.3.6.1.4.1.15497.1.1.1.19.0',
      mailTransferThreads => '1.3.6.1.4.1.15497.1.1.1.20.0',
  },
  # END Cisco
  'SW-MIB' => {
      sw => '1.3.6.1.4.1.1588.2.1.1.1',
      swFirmwareVersion => '1.3.6.1.4.1.1588.2.1.1.1.1.6.0',
      swSensorTable => '1.3.6.1.4.1.1588.2.1.1.1.1.22',
      swSensorEntry => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1',
      swSensorIndex => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1.1',
      swSensorType => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1.2',
      swSensorTypeDefinition => {
          1 => 'temperature',
          2 => 'fan',
          3 => 'power-supply',
      },
      swSensorStatus => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1.3',
      swSensorStatusDefinition => {
          1 => 'unknown',
          2 => 'faulty',
          3 => 'below-min',
          4 => 'nominal',
          5 => 'above-max',
          6 => 'absent',
      },
      # the value, -2147483648, represents an unknown quantity
      # In V2.0, the temperature sensor
      # value will be in Celsius; the fan value will be in RPM
      # (revoluation per minute); and the power supply sensor reading
      # will be unknown.
      swSensorValue => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1.4',
      swSensorInfo => '1.3.6.1.4.1.1588.2.1.1.1.1.22.1.5',

      swFwFabricWatchLicense => '1.3.6.1.4.1.1588.2.1.1.1.10.1.0',
      swFwFabricWatchLicenseDefinition => {
          1 => 'swFwLicensed',
          2 => 'swFwNotLicensed',
      },

      swFwThresholdTable => '1.3.6.1.4.1.1588.2.1.1.1.10.3',
      swFwThresholdEntry => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1',
      swFwThresholdIndex => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.1',
      swFwStatus => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.2',
      swFwName => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.3',
      swFwLabel => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.4',
      swFwCurVal => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.5',
      swFwLastEvent => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.6',
      swFwLastEventVal => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.7',
      swFwLastEventTime => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.8',
      swFwLastState => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.9',
      swFwBehaviorType => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.10',
      swFwBehaviorInt => '1.3.6.1.4.1.1588.2.1.1.1.10.3.1.11',

      swCpuOrMemoryUsage => '1.3.6.1.4.1.1588.2.1.1.1.26',
      swCpuUsage => '1.3.6.1.4.1.1588.2.1.1.1.26.1',
        # The system's CPU usage.
      swCpuNoOfRetries => '1.3.6.1.4.1.1588.2.1.1.1.26.2',
        # The number of times the system should take a CPU utilization sample before sending the CPU utilization trap.
      swCpuUsageLimit => '1.3.6.1.4.1.1588.2.1.1.1.26.3',
        # The CPU usage limit.
      swCpuPollingInterval => '1.3.6.1.4.1.1588.2.1.1.1.26.4',
        # The time after which the next CPU usage value will be recorded.
      swCpuAction => '1.3.6.1.4.1.1588.2.1.1.1.26.5',
        # The action to be taken if the CPU usage exceeds the specified threshold limit.
      swMemUsage => '1.3.6.1.4.1.1588.2.1.1.1.26.6',
        # The system's memory usage.
      swMemNoOfRetries => '1.3.6.1.4.1.1588.2.1.1.1.26.7',
        # The number of times the system should take a memory usage sample before sending the Fabric Watch trap that indicates the current memory usage.
      swMemUsageLimit => '1.3.6.1.4.1.1588.2.1.1.1.26.8',
        # The memory usage limit. This OID specifies the in-between threshold value.
      swMemPollingInterval => '1.3.6.1.4.1.1588.2.1.1.1.26.9',
        # The time after which the next memory usage sample will be taken
      swMemAction => '1.3.6.1.4.1.1588.2.1.1.1.26.10',
        # The action to be taken if the memory usage exceed the specified threshold limit.
      swMemUsageLimit1 => '1.3.6.1.4.1.1588.2.1.1.1.26.11',
        # This OID specifies the low threshold value.
      swMemUsageLimit3 => '1.3.6.1.4.1.1588.2.1.1.1.26.12',
        # This OID specifies the high threshold value.
  },
  'ENTITY-MIB' => {
      entPhysicalTable => '1.3.6.1.2.1.47.1.1.1',
      entPhysicalEntry => '1.3.6.1.2.1.47.1.1.1.1',
      entPhysicalIndex => '1.3.6.1.2.1.47.1.1.1.1.1',
      entPhysicalDescr => '1.3.6.1.2.1.47.1.1.1.1.2',
      entPhysicalVendorType => '1.3.6.1.2.1.47.1.1.1.1.3',
      entPhysicalContainedIn => '1.3.6.1.2.1.47.1.1.1.1.4',
      entPhysicalClass => '1.3.6.1.2.1.47.1.1.1.1.5',
      entPhysicalClassDefinition => 'ENTITY-MIB::PhysicalClass',
      entPhysicalParentRelPos => '1.3.6.1.2.1.47.1.1.1.1.6',
      entPhysicalName => '1.3.6.1.2.1.47.1.1.1.1.7',
      entPhysicalHardwareRev => '1.3.6.1.2.1.47.1.1.1.1.8',
      entPhysicalFirmwareRev => '1.3.6.1.2.1.47.1.1.1.1.9',
      entPhysicalSoftwareRev => '1.3.6.1.2.1.47.1.1.1.1.10',
      entPhysicalSerialNum => '1.3.6.1.2.1.47.1.1.1.1.11',
      entPhysicalMfgName => '1.3.6.1.2.1.47.1.1.1.1.12',
      entPhysicalModelName => '1.3.6.1.2.1.47.1.1.1.1.13',
      entPhysicalAlias => '1.3.6.1.2.1.47.1.1.1.1.14',
      entPhysicalAssetID => '1.3.6.1.2.1.47.1.1.1.1.15',
      entPhysicalIsFRU => '1.3.6.1.2.1.47.1.1.1.1.16',
      entPhysicalMfgDate => '1.3.6.1.2.1.47.1.1.1.1.17',
      entPhysicalUris => '1.3.6.1.2.1.47.1.1.1.1.18',

  },
  'UCD-SNMP-MIB' => {
      laTable => '1.3.6.1.4.1.2021.10',
      laEntry => '1.3.6.1.4.1.2021.10.1',
      laIndex => '1.3.6.1.4.1.2021.10.1.1',
      laNames => '1.3.6.1.4.1.2021.10.1.2',
      laLoad => '1.3.6.1.4.1.2021.10.1.3',
      laConfig => '1.3.6.1.4.1.2021.10.1.4',
      laLoadInt => '1.3.6.1.4.1.2021.10.1.5',
      laLoadFloat => '1.3.6.1.4.1.2021.10.1.6',
      laErrorFlag => '1.3.6.1.4.1.2021.10.1.100',
      laErrMessage => '1.3.6.1.4.1.2021.10.1.101',

      memoryGroup => '1.3.6.1.4.1.2021.4',
      memIndex => '1.3.6.1.4.1.2021.4.1',
      memErrorName => '1.3.6.1.4.1.2021.4.2',
      memTotalSwap => '1.3.6.1.4.1.2021.4.3',
      memAvailSwap => '1.3.6.1.4.1.2021.4.4',
      memTotalReal => '1.3.6.1.4.1.2021.4.5',
      memAvailReal => '1.3.6.1.4.1.2021.4.6',
      memTotalSwapTXT => '1.3.6.1.4.1.2021.4.7',
      memAvailSwapTXT => '1.3.6.1.4.1.2021.4.8',
      memTotalRealTXT => '1.3.6.1.4.1.2021.4.9',
      memAvailRealTXT => '1.3.6.1.4.1.2021.4.10',
      memTotalFree => '1.3.6.1.4.1.2021.4.11',
      memMinimumSwap => '1.3.6.1.4.1.2021.4.12',
      memShared => '1.3.6.1.4.1.2021.4.13',
      memBuffer => '1.3.6.1.4.1.2021.4.14',
      memCached => '1.3.6.1.4.1.2021.4.15',
      memSwapError => '1.3.6.1.4.1.2021.4.100',
      memSwapErrorMsg => '1.3.6.1.4.1.2021.4.101',

      systemStatsGroup => '1.3.6.1.4.1.2021.11',
      ssIndex => '1.3.6.1.4.1.2021.11.1',
      ssErrorName => '1.3.6.1.4.1.2021.11.2',
      ssSwapIn => '1.3.6.1.4.1.2021.11.3',
      ssSwapOut => '1.3.6.1.4.1.2021.11.4',
      ssIOSent => '1.3.6.1.4.1.2021.11.5',
      ssIOReceive => '1.3.6.1.4.1.2021.11.6',
      ssSysInterrupts => '1.3.6.1.4.1.2021.11.7',
      ssSysContext => '1.3.6.1.4.1.2021.11.8',
      ssCpuUser => '1.3.6.1.4.1.2021.11.9',
      ssCpuSystem => '1.3.6.1.4.1.2021.11.10',
      ssCpuIdle => '1.3.6.1.4.1.2021.11.11',
      ssCpuRawUser => '1.3.6.1.4.1.2021.11.50',
      ssCpuRawNice => '1.3.6.1.4.1.2021.11.51',
      ssCpuRawSystem => '1.3.6.1.4.1.2021.11.52',
      ssCpuRawIdle => '1.3.6.1.4.1.2021.11.53',
  },
  'LM-SENSORS-MIB' => {
    lmSensors => '1.3.6.1.4.1.2021.13.16',
    lmSensorsMIB => '1.3.6.1.4.1.2021.13.16.1',
    lmTempSensorsTable => '1.3.6.1.4.1.2021.13.16.2',
    lmTempSensorsEntry => '1.3.6.1.4.1.2021.13.16.2.1',
    lmTempSensorsIndex => '1.3.6.1.4.1.2021.13.16.2.1.1',
    lmTempSensorsDevice => '1.3.6.1.4.1.2021.13.16.2.1.2',
    lmTempSensorsValue => '1.3.6.1.4.1.2021.13.16.2.1.3',
    lmFanSensorsTable => '1.3.6.1.4.1.2021.13.16.3',
    lmFanSensorsEntry => '1.3.6.1.4.1.2021.13.16.3.1',
    lmFanSensorsIndex => '1.3.6.1.4.1.2021.13.16.3.1.1',
    lmFanSensorsDevice => '1.3.6.1.4.1.2021.13.16.3.1.2',
    lmFanSensorsValue => '1.3.6.1.4.1.2021.13.16.3.1.3',
    lmVoltSensorsTable => '1.3.6.1.4.1.2021.13.16.4',
    lmVoltSensorsEntry => '1.3.6.1.4.1.2021.13.16.4.1',
    lmVoltSensorsIndex => '1.3.6.1.4.1.2021.13.16.4.1.1',
    lmVoltSensorsDevice => '1.3.6.1.4.1.2021.13.16.4.1.2',
    lmVoltSensorsValue => '1.3.6.1.4.1.2021.13.16.4.1.3',
    lmMiscSensorsTable => '1.3.6.1.4.1.2021.13.16.5',
    lmMiscSensorsEntry => '1.3.6.1.4.1.2021.13.16.5.1',
    lmMiscSensorsIndex => '1.3.6.1.4.1.2021.13.16.5.1.1',
    lmMiscSensorsDevice => '1.3.6.1.4.1.2021.13.16.5.1.2',
    lmMiscSensorsValue => '1.3.6.1.4.1.2021.13.16.5.1.3',
  },
  'FCMGMT-MIB' => {
      fcConnUnitTable => '1.3',
      fcConnUnitEntry => '1.3.1',
      fcConnUnitId => '1.3.1.1',
      fcConnUnitGlobalId => '1.3.1.2',
      fcConnUnitType => '1.3',
      fcConnUnitNumPorts => '1.3.1.4',
      fcConnUnitState => '1.3.1.5',
      fcConnUnitStatus => '1.3.1.6',
      fcConnUnitProduct => '1.3.1.7',
      fcConnUnitSerialNo => '1.3.1.8',
      fcConnUnitUpTime => '1.3.1.9',
      fcConnUnitUrl => '1.3.1.10',
      fcConnUnitDomainId => '1.3.1.11',
      fcConnUnitProxyMaster => '1.3.1.12',
      fcConnUnitPrincipal => '1.3.1.13',
      fcConnUnitNumSensors => '1.3.1.14',
      fcConnUnitNumRevs => '1.3.1.15',
      fcConnUnitModuleId => '1.3.1.16',
      fcConnUnitName => '1.3.1.17',
      fcConnUnitInfo => '1.3.1.18',
      fcConnUnitControl => '1.3.1.19',
      fcConnUnitContact => '1.3.1.20',
      fcConnUnitLocation => '1.3.1.21',
      fcConnUnitEventFilter => '1.3.1.22',
      fcConnUnitNumEvents => '1.3.1.23',
      fcConnUnitMaxEvents => '1.3.1.24',
      fcConnUnitEventCurrID => '1.3.1.25',

      fcConnUnitRevsTable => '1.3.6.1.2.1.8888.1.1.4',
      fcConnUnitRevsEntry => '1.3.6.1.2.1.8888.1.1.4.1',
      fcConnUnitRevsIndex => '1.3.6.1.2.1.8888.1.1.4.1.1',
      fcConnUnitRevsRevision => '1.3.6.1.2.1.8888.1.1.4.1.2',
      fcConnUnitRevsDescription => '1.3',

      fcConnUnitSensorTable => '1.3.6.1.2.1.8888.1.1.5',
      fcConnUnitSensorEntry => '1.3.6.1.2.1.8888.1.1.5.1',
      fcConnUnitSensorIndex => '1.3.6.1.2.1.8888.1.1.5.1.1',
      fcConnUnitSensorName => '1.3.6.1.2.1.8888.1.1.5.1.2',
      fcConnUnitSensorStatus => '1.3.6.1.2.1.8888.1.1.5.1.3',
      fcConnUnitSensorStatusDefinition => {
          1 => 'unknown',
          2 => 'other',
          3 => 'ok',
          4 => 'warning',
          5 => 'failed',
      },
      fcConnUnitSensorInfo => '1.3.6.1.2.1.8888.1.1.5.1.4',
      fcConnUnitSensorMessage => '1.3.6.1.2.1.8888.1.1.5.1.5',
      fcConnUnitSensorType => '1.3.6.1.2.1.8888.1.1.5.1.6',
      fcConnUnitSensorTypeDefinition => {
          1 => 'unknown',
          2 => 'other',
          3 => 'battery',
          4 => 'fan',
          5 => 'powerSupply',
          6 => 'transmitter',
          7 => 'enclosure',
          8 => 'board',
          9 => 'receiver',
      },
      fcConnUnitSensorCharacteristic => '1.3.6.1.2.1.8888.1.1.5.1.7',
      fcConnUnitSensorCharacteristicDefinition => {
          1 => 'unknown',
          2 => 'other',
          3 => 'temperature',
          4 => 'pressure',
          5 => 'emf',
          6 => 'currentValue',
          7 => 'airflow',
          8 => 'frequency',
          9 => 'power',
      },

      fcConnUnitPortTable => '1.3.6.1.2.1.8888.1.1.6',
      fcConnUnitPortEntry => '1.3.6.1.2.1.8888.1.1.6.1',
      fcConnUnitPortIndex => '1.3.6.1.2.1.8888.1.1.6.1.1',
      fcConnUnitPortType => '1.3.6.1.2.1.8888.1.1.6.1.2',
      fcConnUnitPortFCClassCap => '1.3',
      fcConnUnitPortFCClassOp => '1.3.6.1.2.1.8888.1.1.6.1.4',
      fcConnUnitPortState => '1.3.6.1.2.1.8888.1.1.6.1.5',
      fcConnUnitPortStatus => '1.3.6.1.2.1.8888.1.1.6.1.6',
      fcConnUnitPortTransmitterType => '1.3.6.1.2.1.8888.1.1.6.1.7',
      fcConnUnitPortModuleType => '1.3.6.1.2.1.8888.1.1.6.1.8',
      fcConnUnitPortWwn => '1.3.6.1.2.1.8888.1.1.6.1.9',
      fcConnUnitPortFCId => '1.3.6.1.2.1.8888.1.1.6.1.10',
      fcConnUnitPortSerialNo => '1.3.6.1.2.1.8888.1.1.6.1.11',
      fcConnUnitPortRevision => '1.3.6.1.2.1.8888.1.1.6.1.12',
      fcConnUnitPortVendor => '1.3.6.1.2.1.8888.1.1.6.1.13',
      fcConnUnitPortSpeed => '1.3.6.1.2.1.8888.1.1.6.1.14',
      fcConnUnitPortControl => '1.3.6.1.2.1.8888.1.1.6.1.15',
      fcConnUnitPortName => '1.3.6.1.2.1.8888.1.1.6.1.16',
      fcConnUnitPortPhysicalNumber => '1.3.6.1.2.1.8888.1.1.6.1.17',
      fcConnUnitPortProtocolCap => '1.3.6.1.2.1.8888.1.1.6.1.18',
      fcConnUnitPortProtocolOp => '1.3.6.1.2.1.8888.1.1.6.1.19',
      fcConnUnitPortNodeWwn => '1.3.6.1.2.1.8888.1.1.6.1.20',
      fcConnUnitPortHWState => '1.3.6.1.2.1.8888.1.1.6.1.21',

      fcConnUnitEventTable => '1.3.6.1.2.1.8888.1.1.7',
      fcConnUnitEventEntry => '1.3.6.1.2.1.8888.1.1.7.1',
      fcConnUnitEventIndex => '1.3.6.1.2.1.8888.1.1.7.1.1',
      fcConnUnitREventTime => '1.3.6.1.2.1.8888.1.1.7.1.2',
      fcConnUnitSEventTime => '1.3',
      fcConnUnitEventSeverity => '1.3.6.1.2.1.8888.1.1.7.1.4',
      fcConnUnitEventType => '1.3.6.1.2.1.8888.1.1.7.1.5',
      fcConnUnitEventObject => '1.3.6.1.2.1.8888.1.1.7.1.6',
      fcConnUnitEventDescr => '1.3.6.1.2.1.8888.1.1.7.1.7',

      fcConnUnitLinkTable => '1.3.6.1.2.1.8888.1.1.8',
      fcConnUnitLinkEntry => '1.3.6.1.2.1.8888.1.1.8.1',
      fcConnUnitLinkIndex => '1.3.6.1.2.1.8888.1.1.8.1.1',
      fcConnUnitLinkNodeIdX => '1.3.6.1.2.1.8888.1.1.8.1.2',
      fcConnUnitLinkPortNumberX => '1.3',
      fcConnUnitLinkPortWwnX => '1.3.6.1.2.1.8888.1.1.8.1.4',
      fcConnUnitLinkNodeIdY => '1.3.6.1.2.1.8888.1.1.8.1.5',
      fcConnUnitLinkPortNumberY => '1.3.6.1.2.1.8888.1.1.8.1.6',
      fcConnUnitLinkPortWwnY => '1.3.6.1.2.1.8888.1.1.8.1.7',
      fcConnUnitLinkAgentAddressY => '1.3.6.1.2.1.8888.1.1.8.1.8',
      fcConnUnitLinkAgentAddressTypeY => '1.3.6.1.2.1.8888.1.1.8.1.9',
      fcConnUnitLinkAgentPortY => '1.3.6.1.2.1.8888.1.1.8.1.10',
      fcConnUnitLinkUnitTypeY => '1.3.6.1.2.1.8888.1.1.8.1.11',
      fcConnUnitLinkConnIdY => '1.3.6.1.2.1.8888.1.1.8.1.12',

      fcConnUnitPortStatTable => '1.3.1',
      fcConnUnitPortStatEntry => '1.3.1.1',
      fcConnUnitPortStatIndex => '1.3.1.1.1',
      fcConnUnitPortStatErrs => '1.3.1.1.2',
      fcConnUnitPortStatTxObjects => '1.3',
      fcConnUnitPortStatRxObjects => '1.3.1.1.4',
      fcConnUnitPortStatTxElements => '1.3.1.1.5',
      fcConnUnitPortStatRxElements => '1.3.1.1.6',
      fcConnUnitPortStatBBCreditZero => '1.3.1.1.7',
      fcConnUnitPortStatInputBuffsFull => '1.3.1.1.8',
      fcConnUnitPortStatFBSYFrames => '1.3.1.1.9',
      fcConnUnitPortStatPBSYFrames => '1.3.1.1.10',
      fcConnUnitPortStatFRJTFrames => '1.3.1.1.11',
      fcConnUnitPortStatPRJTFrames => '1.3.1.1.12',
      fcConnUnitPortStatC1RxFrames => '1.3.1.1.13',
      fcConnUnitPortStatC1TxFrames => '1.3.1.1.14',
      fcConnUnitPortStatC1FBSYFrames => '1.3.1.1.15',
      fcConnUnitPortStatC1PBSYFrames => '1.3.1.1.16',
      fcConnUnitPortStatC1FRJTFrames => '1.3.1.1.17',
      fcConnUnitPortStatC1PRJTFrames => '1.3.1.1.18',
      fcConnUnitPortStatC2RxFrames => '1.3.1.1.19',
      fcConnUnitPortStatC2TxFrames => '1.3.1.1.20',
      fcConnUnitPortStatC2FBSYFrames => '1.3.1.1.21',
      fcConnUnitPortStatC2PBSYFrames => '1.3.1.1.22',
      fcConnUnitPortStatC2FRJTFrames => '1.3.1.1.23',
      fcConnUnitPortStatC2PRJTFrames => '1.3.1.1.24',
      fcConnUnitPortStatC3RxFrames => '1.3.1.1.25',
      fcConnUnitPortStatC3TxFrames => '1.3.1.1.26',
      fcConnUnitPortStatC3Discards => '1.3.1.1.27',
      fcConnUnitPortStatRxMcastObjects => '1.3.1.1.28',
      fcConnUnitPortStatTxMcastObjects => '1.3.1.1.29',
      fcConnUnitPortStatRxBcastObjects => '1.30',
      fcConnUnitPortStatTxBcastObjects => '1.31',
      fcConnUnitPortStatRxLinkResets => '1.32',
      fcConnUnitPortStatTxLinkResets => '1.33',
      fcConnUnitPortStatLinkResets => '1.34',
      fcConnUnitPortStatRxOfflineSeqs => '1.35',
      fcConnUnitPortStatTxOfflineSeqs => '1.36',
      fcConnUnitPortStatOfflineSeqs => '1.37',
      fcConnUnitPortStatLinkFailures => '1.38',
      fcConnUnitPortStatInvalidCRC => '1.39',
      fcConnUnitPortStatInvalidTxWords => '1.3.1.1.40',
      fcConnUnitPortStatPSPErrs => '1.3.1.1.41',
      fcConnUnitPortStatLossOfSignal => '1.3.1.1.42',
      fcConnUnitPortStatLossOfSync => '1.3.1.1.43',
      fcConnUnitPortStatInvOrderedSets => '1.3.1.1.44',
      fcConnUnitPortStatFramesTooLong => '1.3.1.1.45',
      fcConnUnitPortStatFramesTooShort => '1.3.1.1.46',
      fcConnUnitPortStatAddressErrs => '1.3.1.1.47',
      fcConnUnitPortStatDelimiterErrs => '1.3.1.1.48',
      fcConnUnitPortStatEncodingErrs => '1.3.1.1.49',

      fcConnUnitSnsMaxRows => '1.3.6.1.2.1.8888.1.1.9.0',
      fcConnUnitSnsTable => '1.3.6.1.2.1.8888.1.4.1',
      fcConnUnitSnsEntry => '1.3.6.1.2.1.8888.1.4.1.1',
      fcConnUnitSnsPortIndex => '1.3.6.1.2.1.8888.1.4.1.1.1',
      fcConnUnitSnsPortIdentifier => '1.3.6.1.2.1.8888.1.4.1.1.2',
      fcConnUnitSnsPortName => '1.3',
      fcConnUnitSnsNodeName => '1.3.6.1.2.1.8888.1.4.1.1.4',
      fcConnUnitSnsClassOfSvc => '1.3.6.1.2.1.8888.1.4.1.1.5',
      fcConnUnitSnsNodeIPAddress => '1.3.6.1.2.1.8888.1.4.1.1.6',
      fcConnUnitSnsProcAssoc => '1.3.6.1.2.1.8888.1.4.1.1.7',
      fcConnUnitSnsFC4Type => '1.3.6.1.2.1.8888.1.4.1.1.8',
      fcConnUnitSnsPortType => '1.3.6.1.2.1.8888.1.4.1.1.9',
      fcConnUnitSnsPortIPAddress => '1.3.6.1.2.1.8888.1.4.1.1.10',
      fcConnUnitSnsFabricPortName => '1.3.6.1.2.1.8888.1.4.1.1.11',
      fcConnUnitSnsHardAddress => '1.3.6.1.2.1.8888.1.4.1.1.12',
      fcConnUnitSnsSymbolicPortName => '1.3.6.1.2.1.8888.1.4.1.1.13',
      fcConnUnitSnsSymbolicNodeName => '1.3.6.1.2.1.8888.1.4.1.1.14',
  },
  'FCEOS-MIB' => {
      fcEosSysCurrentDate => '1.3.6.1.4.1.289.2.1.1.2.1.1.0',
      fcEosSysBootDate => '1.3.6.1.4.1.289.2.1.1.2.1.2.0',
      fcEosSysFirmwareVersion => '1.3.6.1.4.1.289.2.1.1.2.1.3.0',
      fcEosSysTypeNum => '1.3.6.1.4.1.289.2.1.1.2.1.4.0',
      fcEosSysModelNum => '1.3.6.1.4.1.289.2.1.1.2.1.5.0',
      fcEosSysMfg => '1.3.6.1.4.1.289.2.1.1.2.1.6.0',
      fcEosSysPlantOfMfg => '1.3.6.1.4.1.289.2.1.1.2.1.7.0',
      fcEosSysEcLevel => '1.3.6.1.4.1.289.2.1.1.2.1.8.0',
      fcEosSysSerialNum => '1.3.6.1.4.1.289.2.1.1.2.1.9.0',
      fcEosSysOperStatus => '1.3.6.1.4.1.289.2.1.1.2.1.10.0',
      fcEosSysOperStatusDefinition => {
          1 => 'operational',
          2 => 'redundant-failure',
          3 => 'minor-failure',
          4 => 'major-failure',
          5 => 'not-operational',
      },
      fcEosSysState => '1.3.6.1.4.1.289.2.1.1.2.1.11.0',
      fcEosSysAdmStatus => '1.3.6.1.4.1.289.2.1.1.2.1.12.0',
      fcEosSysConfigSpeed => '1.3.6.1.4.1.289.2.1.1.2.1.13.0',
      fcEosSysOpenTrunking => '1.3.6.1.4.1.289.2.1.1.2.1.14.0',

      fcEosFruTable => '1.3.6.1.4.1.289.2.1.1.2.2.1',
      fcEosFruEntry => '1.3.6.1.4.1.289.2.1.1.2.2.1.1',
      fcEosFruCode => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.1',
      fcEosFruCodeDefinition => {
          1 => 'fru-bkplane', # Backplane 
          2 => 'fru-ctp', # Control Processor card 
          3 => 'fru-sbar', # Serial Crossbar 
          4 => 'fru-fan2', # Center fan module 
          5 => 'fru-fan', # Fan module 
          6 => 'fru-power', # Power supply module 
          7 => 'fru-reserved', # Reserved, not used 
          8 => 'fru-glsl', # Longwave, Single-Mode, LC connector, 1 Gig 
          9 => 'fru-gsml', # Shortwave, Multi-Mode, LC connector, 1 Gig 
          10 => 'fru-gxxl', # Mixed, LC connector, 1 Gig 
          11 => 'fru-gsf1', # SFO pluggable, 1 Gig 
          12 => 'fru-gsf2', # SFO pluggable, 2 Gig 
          13 => 'fru-glsr', # Longwave, Single-Mode, MT-RJ connector, 1 Gig 
          14 => 'fru-gsmr', # Shortwave, Multi-Mode, MT-RJ connector, 1 Gig 
          15 => 'fru-gxxr', # Mixed, MT-RJ connector, 1 Gig 
          16 => 'fru-fint1', # F-Port, internal, 1 Gig 
      },
      fcEosFruPosition => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.2',
      fcEosFruStatus => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.3',
      fcEosFruStatusDefinition => {
          0 => 'unknown',
          1 => 'active',
          2 => 'backup',
          3 => 'update-busy',
          4 => 'failed',
      },
      fcEosFruPartNumber => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.4',
      fcEosFruSerialNumber => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.5',
      fcEosFruPowerOnHours => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.6',
      fcEosFruTestDate => '1.3.6.1.4.1.289.2.1.1.2.2.1.1.7',

      fcEosTATable => '1.3.6.1.4.1.289.2.1.1.2.6.1',
      fcEosTAEntry => '1.3.6.1.4.1.289.2.1.1.2.6.1.1',
      fcEosTAIndex => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.1',
      fcEosTAName => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.2',
      fcEosTAState => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.3',
      fcEosTAType => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.4',
      fcEosTAPortType => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.5',
      fcEosTAPortList => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.6',
      fcEosTAInterval => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.7',
      fcEosTATriggerValue => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.8',
      fcEosTTADirection => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.9',
      fcEosTTATriggerDuration => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.10',
      fcEosCTACounter => '1.3.6.1.4.1.289.2.1.1.2.6.1.1.11',
  },
  'F5-BIGIP-SYSTEM-MIB' => {
# http://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/bigip9_2_2mgmt/BIG-IP_9_2_2nsm_guide-16-1.html
# http://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/tmos_management_guide_10_0_0/tmos_appendix_a_traps.html
# http://support.f5.com/kb/en-us/solutions/public/9000/400/sol9476.html
      sysStatMemoryTotal => '1.3.6.1.4.1.3375.2.1.1.2.1.44.0',
      sysStatMemoryUsed => '1.3.6.1.4.1.3375.2.1.1.2.1.45.0',
      sysHostMemoryTotal => '1.3.6.1.4.1.3375.2.1.7.1.1.0',
      sysHostMemoryUsed => '1.3.6.1.4.1.3375.2.1.7.1.2.0',
# http://www.midnight-visions.de/f5-bigip-und-snmp/
      sysStatTmTotalCycles => '1.3.6.1.4.1.3375.2.1.1.2.1.41.0',
      sysStatTmIdleCycles => '1.3.6.1.4.1.3375.2.1.1.2.1.42.0',
      sysStatTmSleepCycles => '1.3.6.1.4.1.3375.2.1.1.2.1.43.0',

      sysPlatformInfoName => '1.3.6.1.4.1.3375.2.1.3.5.1.0',
      sysPlatformInfoMarketingName => '1.3.6.1.4.1.3375.2.1.3.5.2.0',

      sysPhysicalDiskTable => '1.3.6.1.4.1.3375.2.1.7.7.2',
      sysPhysicalDiskEntry => '1.3.6.1.4.1.3375.2.1.7.7.2.1',
      sysPhysicalDiskSerialNumber => '1.3.6.1.4.1.3375.2.1.7.7.2.1.1',
      sysPhysicalDiskSlotId => '1.3.6.1.4.1.3375.2.1.7.7.2.1.2',
      sysPhysicalDiskName => '1.3.6.1.4.1.3375.2.1.7.7.2.1.3',
      sysPhysicalDiskIsArrayMember => '1.3.6.1.4.1.3375.2.1.7.7.2.1.4',
      sysPhysicalDiskIsArrayMemberDefinition => {
          0 => 'false',
          1 => 'true',
      },
      sysPhysicalDiskArrayStatus => '1.3.6.1.4.1.3375.2.1.7.7.2.1.5',
      sysPhysicalDiskArrayStatusDefinition => {
          0 => 'undefined',
          1 => 'ok',
          2 => 'replicating',
          3 => 'missing',
          4 => 'failed',
      },

      sysCpuNumber => '1.3.6.1.4.1.3375.2.1.3.1.1.0',
      sysCpuTable => '1.3.6.1.4.1.3375.2.1.3.1.2',
      sysCpuEntry => '1.3.6.1.4.1.3375.2.1.3.1.2.1',
      sysCpuIndex => '1.3.6.1.4.1.3375.2.1.3.1.2.1.1',
      sysCpuTemperature => '1.3.6.1.4.1.3375.2.1.3.1.2.1.2',
      sysCpuFanSpeed => '1.3.6.1.4.1.3375.2.1.3.1.2.1.3',
      sysCpuName => '1.3.6.1.4.1.3375.2.1.3.1.2.1.4',
      sysCpuSlot => '1.3.6.1.4.1.3375.2.1.3.1.2.1.5',

      sysChassisFan => '1.3.6.1.4.1.3375.2.1.3.2.1',
      sysChassisFanNumber => '1.3.6.1.4.1.3375.2.1.3.2.1.1.0',
      sysChassisFanTable => '1.3.6.1.4.1.3375.2.1.3.2.1.2',
      sysChassisFanEntry => '1.3.6.1.4.1.3375.2.1.3.2.1.2.1',
      sysChassisFanIndex => '1.3.6.1.4.1.3375.2.1.3.2.1.2.1.1',
      sysChassisFanStatus => '1.3.6.1.4.1.3375.2.1.3.2.1.2.1.2',
      sysChassisFanStatusDefinition => {
          0 => 'bad',
          1 => 'good',
          2 => 'notpresent',
      },
      sysChassisFanSpeed => '1.3.6.1.4.1.3375.2.1.3.2.1.2.1.3',

      sysChassisPowerSupply => '1.3.6.1.4.1.3375.2.1.3.2.2',
      sysChassisPowerSupplyNumber => '1.3.6.1.4.1.3375.2.1.3.2.2.1.0',
      sysChassisPowerSupplyTable => '1.3.6.1.4.1.3375.2.1.3.2.2.2',
      sysChassisPowerSupplyEntry => '1.3.6.1.4.1.3375.2.1.3.2.2.2.1',
      sysChassisPowerSupplyIndex => '1.3.6.1.4.1.3375.2.1.3.2.2.2.1.1',
      sysChassisPowerSupplyStatus => '1.3.6.1.4.1.3375.2.1.3.2.2.2.1.2',
      sysChassisPowerSupplyStatusDefinition => {
          0 => 'bad',
          1 => 'good',
          2 => 'notpresent',
      },

      sysChassisTemp => '1.3.6.1.4.1.3375.2.1.3.2.3',
      sysChassisTempNumber => '1.3.6.1.4.1.3375.2.1.3.2.3.1.0',
      sysChassisTempTable => '1.3.6.1.4.1.3375.2.1.3.2.3.2',
      sysChassisTempEntry => '1.3.6.1.4.1.3375.2.1.3.2.3.2.1',
      sysChassisTempIndex => '1.3.6.1.4.1.3375.2.1.3.2.3.2.1.1',
      sysChassisTempTemperature => '1.3.6.1.4.1.3375.2.1.3.2.3.2.1.2',

      sysProduct => '1.3.6.1.4.1.3375.2.1.4',
      sysProductName => '1.3.6.1.4.1.3375.2.1.4.1.0',
      sysProductVersion => '1.3.6.1.4.1.3375.2.1.4.2.0',
      sysProductBuild => '1.3.6.1.4.1.3375.2.1.4.3.0',
      sysProductEdition => '1.3.6.1.4.1.3375.2.1.4.4.0',
      sysProductDate => '1.3.6.1.4.1.3375.2.1.4.5.0',

      sysSubMemory => '1.3.6.1.4.1.3375.2.1.5',
      sysSubMemoryResetStats => '1.3.6.1.4.1.3375.2.1.5.1.0',
      sysSubMemoryNumber => '1.3.6.1.4.1.3375.2.1.5.2.0',
      sysSubMemoryTable => '1.3.6.1.4.1.3375.2.1.5.3',
      sysSubMemoryEntry => '1.3.6.1.4.1.3375.2.1.5.3.1',
      sysSubMemoryName => '1.3.6.1.4.1.3375.2.1.5.3.1.1',
      sysSubMemoryAllocated => '1.3.6.1.4.1.3375.2.1.5.3.1.2',
      sysSubMemoryMaxAllocated => '1.3.6.1.4.1.3375.2.1.5.3.1.3',
      sysSubMemorySize => '1.3.6.1.4.1.3375.2.1.5.3.1.4',

      sysSystem => '1.3.6.1.4.1.3375.2.1.6',
      sysSystemName => '1.3.6.1.4.1.3375.2.1.6.1.0',
      sysSystemNodeName => '1.3.6.1.4.1.3375.2.1.6.2.0',
      sysSystemRelease => '1.3.6.1.4.1.3375.2.1.6.3.0',
      sysSystemVersion => '1.3.6.1.4.1.3375.2.1.6.4.0',
      sysSystemMachine => '1.3.6.1.4.1.3375.2.1.6.5.0',
      sysSystemUptime => '1.3.6.1.4.1.3375.2.1.6.6.0',
      bigipSystemGroups => '1.3.6.1.4.1.3375.2.5.2.1',
  },
  'HP-ICF-CHASSIS-MIB' => {
      hpicfSensorTable => '1.3.6.1.4.1.11.2.14.11.1.2.6',
      hpicfSensorEntry => '1.3.6.1.4.1.11.2.14.11.1.2.6.1',
      hpicfSensorIndex => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.1',
      hpicfSensorObjectId => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.2',
      hpicfSensorObjectIdDefinition => {
          1 => 'fan sensor',
          2 => 'power supply',
          3 => 'redundant power supply',
          4 => 'over-temperature sensor',
      },
      hpicfSensorNumber => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.3',
      hpicfSensorStatus => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.4',
      hpicfSensorStatusDefinition => {
          1 => 'unknown',
          2 => 'bad',
          3 => 'warning',
          4 => 'good',
          5 => 'notPresent',
      },
      hpicfSensorWarnings => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.5',
      hpicfSensorFailures => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.6',
      hpicfSensorDescr => '1.3.6.1.4.1.11.2.14.11.1.2.6.1.7',
#hpicfSensorObjectId.1 = icfFanSensor
#hpicfSensorObjectId.2 = icfPowerSupplySensor
#hpicfSensorObjectId.3 = icfPowerSupplySensor
#hpicfSensorObjectId.4 = icfTemperatureSensor

#hpicfSensorDescr.1 = Fan Sensor
#hpicfSensorDescr.2 = Power Supply Sensor
#hpicfSensorDescr.3 = Redundant Power Supply Sensor
#hpicfSensorDescr.4 = Over-temperature Sensor

  },
  'F5-BIGIP-LOCAL-MIB' => {
    ltmPoolNumber => '1.3.6.1.4.1.3375.2.2.5.1.1.0',
    ltmPoolTable => '1.3.6.1.4.1.3375.2.2.5.1.2',
    ltmPoolEntry => '1.3.6.1.4.1.3375.2.2.5.1.2.1',
    ltmPoolName => '1.3.6.1.4.1.3375.2.2.5.1.2.1.1',
    ltmPoolLbMode => '1.3.6.1.4.1.3375.2.2.5.1.2.1.2',
    ltmPoolActionOnServiceDown => '1.3.6.1.4.1.3375.2.2.5.1.2.1.3',
    ltmPoolMinUpMembers => '1.3.6.1.4.1.3375.2.2.5.1.2.1.4',
    ltmPoolMinUpMembersEnable => '1.3.6.1.4.1.3375.2.2.5.1.2.1.5',
    ltmPoolMinUpMemberAction => '1.3.6.1.4.1.3375.2.2.5.1.2.1.6',
    ltmPoolMinActiveMembers => '1.3.6.1.4.1.3375.2.2.5.1.2.1.7',
    ltmPoolActiveMemberCnt => '1.3.6.1.4.1.3375.2.2.5.1.2.1.8',
    ltmPoolDisallowSnat => '1.3.6.1.4.1.3375.2.2.5.1.2.1.9',
    ltmPoolDisallowNat => '1.3.6.1.4.1.3375.2.2.5.1.2.1.10',
    ltmPoolSimpleTimeout => '1.3.6.1.4.1.3375.2.2.5.1.2.1.11',
    ltmPoolIpTosToClient => '1.3.6.1.4.1.3375.2.2.5.1.2.1.12',
    ltmPoolIpTosToServer => '1.3.6.1.4.1.3375.2.2.5.1.2.1.13',
    ltmPoolLinkQosToClient => '1.3.6.1.4.1.3375.2.2.5.1.2.1.14',
    ltmPoolLinkQosToServer => '1.3.6.1.4.1.3375.2.2.5.1.2.1.15',
    ltmPoolDynamicRatioSum => '1.3.6.1.4.1.3375.2.2.5.1.2.1.16',
    ltmPoolMonitorRule => '1.3.6.1.4.1.3375.2.2.5.1.2.1.17',
    ltmPoolAvailabilityState => '1.3.6.1.4.1.3375.2.2.5.1.2.1.18',
    ltmPoolEnabledState => '1.3.6.1.4.1.3375.2.2.5.1.2.1.19',
    ltmPoolDisabledParentType => '1.3.6.1.4.1.3375.2.2.5.1.2.1.20',
    ltmPoolStatusReason => '1.3.6.1.4.1.3375.2.2.5.1.2.1.21',
    ltmPoolSlowRampTime => '1.3.6.1.4.1.3375.2.2.5.1.2.1.22',
    ltmPoolMemberCnt => '1.3.6.1.4.1.3375.2.2.5.1.2.1.23',

    ltmPoolStatTable => '1.3.6.1.4.1.3375.2.2.5.2.3',
    ltmPoolStatEntry => '1.3.6.1.4.1.3375.2.2.5.2.3.1',
    ltmPoolStatName => '1.3.6.1.4.1.3375.2.2.5.2.3.1.1',
    ltmPoolStatServerCurConns => '1.3.6.1.4.1.3375.2.2.5.2.3.1.8',
    ltmPoolStatCurSessions => '1.3.6.1.4.1.3375.2.2.5.2.3.1.31',

    ltmPoolMemberTable => '1.3.6.1.4.1.3375.2.2.5.3.2',
    ltmPoolMemberEntry => '1.3.6.1.4.1.3375.2.2.5.3.2.1',
    ltmPoolMemberPoolName => '1.3.6.1.4.1.3375.2.2.5.3.2.1.1',
    ltmPoolMemberAddrType => '1.3.6.1.4.1.3375.2.2.5.3.2.1.2',
    ltmPoolMemberAddr => '1.3.6.1.4.1.3375.2.2.5.3.2.1.3',
    ltmPoolMemberPort => '1.3.6.1.4.1.3375.2.2.5.3.2.1.4',
    ltmPoolMemberConnLimit => '1.3.6.1.4.1.3375.2.2.5.3.2.1.5',
    ltmPoolMemberRatio => '1.3.6.1.4.1.3375.2.2.5.3.2.1.6',
    ltmPoolMemberWeight => '1.3.6.1.4.1.3375.2.2.5.3.2.1.7',
    ltmPoolMemberPriority => '1.3.6.1.4.1.3375.2.2.5.3.2.1.8',
    ltmPoolMemberDynamicRatio => '1.3.6.1.4.1.3375.2.2.5.3.2.1.9',
    ltmPoolMemberMonitorState => '1.3.6.1.4.1.3375.2.2.5.3.2.1.10',
    ltmPoolMemberMonitorStateDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolMemberMonitorState',
    ltmPoolMemberMonitorStatus => '1.3.6.1.4.1.3375.2.2.5.3.2.1.11',
    ltmPoolMemberMonitorStatusDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolMemberMonitorStatus',
    ltmPoolMemberNewSessionEnable => '1.3.6.1.4.1.3375.2.2.5.3.2.1.12',
    ltmPoolMemberSessionStatus => '1.3.6.1.4.1.3375.2.2.5.3.2.1.13',
    ltmPoolMemberMonitorRule => '1.3.6.1.4.1.3375.2.2.5.3.2.1.14',
    ltmPoolMemberAvailabilityState => '1.3.6.1.4.1.3375.2.2.5.3.2.1.15',
    ltmPoolMemberEnabledState => '1.3.6.1.4.1.3375.2.2.5.3.2.1.16',
    ltmPoolMemberDisabledParentType => '1.3.6.1.4.1.3375.2.2.5.3.2.1.17',
    ltmPoolMemberStatusReason => '1.3.6.1.4.1.3375.2.2.5.3.2.1.18',
    ltmPoolMemberNodeName => '1.3.6.1.4.1.3375.2.2.5.3.2.1.19',

    ltmPoolMemberStat => '1.3.6.1.4.1.3375.2.2.5.4',
    ltmPoolMemberStatResetStats => '1.3.6.1.4.1.3375.2.2.5.4.1',
    ltmPoolMemberStatNumber => '1.3.6.1.4.1.3375.2.2.5.4.2',
    ltmPoolMemberStatTable => '1.3.6.1.4.1.3375.2.2.5.4.3',
    ltmPoolMemberStatEntry => '1.3.6.1.4.1.3375.2.2.5.4.3.1',
    ltmPoolMemberStatPoolName => '1.3.6.1.4.1.3375.2.2.5.4.3.1.1',
    ltmPoolMemberStatAddrType => '1.3.6.1.4.1.3375.2.2.5.4.3.1.2',
    ltmPoolMemberStatAddr => '1.3.6.1.4.1.3375.2.2.5.4.3.1.3',
    ltmPoolMemberStatPort => '1.3.6.1.4.1.3375.2.2.5.4.3.1.4',
    ltmPoolMemberStatServerPktsIn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.5',
    ltmPoolMemberStatServerBytesIn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.6',
    ltmPoolMemberStatServerPktsOut => '1.3.6.1.4.1.3375.2.2.5.4.3.1.7',
    ltmPoolMemberStatServerBytesOut => '1.3.6.1.4.1.3375.2.2.5.4.3.1.8',
    ltmPoolMemberStatServerMaxConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.9',
    ltmPoolMemberStatServerTotConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.10',
    ltmPoolMemberStatServerCurConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.11',
    ltmPoolMemberStatPvaPktsIn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.12',
    ltmPoolMemberStatPvaBytesIn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.13',
    ltmPoolMemberStatPvaPktsOut => '1.3.6.1.4.1.3375.2.2.5.4.3.1.14',
    ltmPoolMemberStatPvaBytesOut => '1.3.6.1.4.1.3375.2.2.5.4.3.1.15',
    ltmPoolMemberStatPvaMaxConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.16',
    ltmPoolMemberStatPvaTotConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.17',
    ltmPoolMemberStatPvaCurConns => '1.3.6.1.4.1.3375.2.2.5.4.3.1.18',
    ltmPoolMemberStatTotRequests => '1.3.6.1.4.1.3375.2.2.5.4.3.1.19',
    ltmPoolMemberStatTotPvaAssistConn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.20',
    ltmPoolMemberStatCurrPvaAssistConn => '1.3.6.1.4.1.3375.2.2.5.4.3.1.21',
    ltmPoolMemberStatConnqDepth => '1.3.6.1.4.1.3375.2.2.5.4.3.1.22',
    ltmPoolMemberStatConnqAgeHead => '1.3.6.1.4.1.3375.2.2.5.4.3.1.23',
    ltmPoolMemberStatConnqAgeMax => '1.3.6.1.4.1.3375.2.2.5.4.3.1.24',
    ltmPoolMemberStatConnqAgeEma => '1.3.6.1.4.1.3375.2.2.5.4.3.1.25',
    ltmPoolMemberStatConnqAgeEdm => '1.3.6.1.4.1.3375.2.2.5.4.3.1.26',
    ltmPoolMemberStatConnqServiced => '1.3.6.1.4.1.3375.2.2.5.4.3.1.27',
    ltmPoolMemberStatNodeName => '1.3.6.1.4.1.3375.2.2.5.4.3.1.28',
    ltmPoolMemberStatCurSessions => '1.3.6.1.4.1.3375.2.2.5.4.3.1.29',

    ltmPoolStatusNumber => '1.3.6.1.4.1.3375.2.2.5.5.1.0',
    ltmPoolStatusTable => '1.3.6.1.4.1.3375.2.2.5.5.2',
    ltmPoolStatusEntry => '1.3.6.1.4.1.3375.2.2.5.5.2.1',
    ltmPoolStatusName => '1.3.6.1.4.1.3375.2.2.5.5.2.1.1',
    ltmPoolStatusAvailState => '1.3.6.1.4.1.3375.2.2.5.5.2.1.2',
    ltmPoolStatusAvailStateDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolStatusAvailState',
    ltmPoolStatusEnabledState => '1.3.6.1.4.1.3375.2.2.5.5.2.1.3',
    ltmPoolStatusEnabledStateDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolStatusEnabledState',
    ltmPoolStatusParentType => '1.3.6.1.4.1.3375.2.2.5.5.2.1.4',
    ltmPoolStatusDetailReason => '1.3.6.1.4.1.3375.2.2.5.5.2.1.5',

    ltmPoolMbrStatusNumber => '1.3.6.1.4.1.3375.2.2.5.6.1.0',
    ltmPoolMbrStatusTable => '1.3.6.1.4.1.3375.2.2.5.6.2',
    ltmPoolMbrStatusEntry => '1.3.6.1.4.1.3375.2.2.5.6.2.1',
    ltmPoolMbrStatusPoolName => '1.3.6.1.4.1.3375.2.2.5.6.2.1.1',
    ltmPoolMbrStatusAddrType => '1.3.6.1.4.1.3375.2.2.5.6.2.1.2',
    ltmPoolMbrStatusAddr => '1.3.6.1.4.1.3375.2.2.5.6.2.1.3',
    ltmPoolMbrStatusPort => '1.3.6.1.4.1.3375.2.2.5.6.2.1.4',
    ltmPoolMbrStatusAvailState => '1.3.6.1.4.1.3375.2.2.5.6.2.1.5',
    ltmPoolMbrStatusAvailStateDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolMbrStatusAvailState',
    ltmPoolMbrStatusEnabledState => '1.3.6.1.4.1.3375.2.2.5.6.2.1.6',
    ltmPoolMbrStatusEnabledStateDefinition => 'F5-BIGIP-LOCAL-MIB::ltmPoolMbrStatusEnabledState',
    ltmPoolMbrStatusParentType => '1.3.6.1.4.1.3375.2.2.5.6.2.1.7',
    ltmPoolMbrStatusDetailReason => '1.3.6.1.4.1.3375.2.2.5.6.2.1.8',
    ltmPoolMbrStatusNodeName => '1.3.6.1.4.1.3375.2.2.5.6.2.1.9',

    ltmNodeAddrStatusTable => '1.3.6.1.4.1.3375.2.2.4.3.2',
    ltmNodeAddrStatusEntry => '1.3.6.1.4.1.3375.2.2.4.3.2.1',
    ltmNodeAddrStatusAddrType => '1.3.6.1.4.1.3375.2.2.4.3.2.1.1',
    ltmNodeAddrStatusAddr => '1.3.6.1.4.1.3375.2.2.4.3.2.1.2',
    ltmNodeAddrStatusAvailState => '1.3.6.1.4.1.3375.2.2.4.3.2.1.3',
    ltmNodeAddrStatusEnabledState => '1.3.6.1.4.1.3375.2.2.4.3.2.1.4',
    ltmNodeAddrStatusParentType => '1.3.6.1.4.1.3375.2.2.4.3.2.1.5',
    ltmNodeAddrStatusDetailReason => '1.3.6.1.4.1.3375.2.2.4.3.2.1.6',
    ltmNodeAddrStatusName => '1.3.6.1.4.1.3375.2.2.4.3.2.1.7',
  },
  'LOAD-BAL-SYSTEM-MIB' => {
    poolTable => '1.3.6.1.4.1.3375.1.1.7.2',
    poolEntry => '1.3.6.1.4.1.3375.1.1.7.2.1',
    poolName => '1.3.6.1.4.1.3375.1.1.7.2.1.1',
    poolLBMode => '1.3.6.1.4.1.3375.1.1.7.2.1.2',
    poolDependent => '1.3.6.1.4.1.3375.1.1.7.2.1.3',
    poolMemberQty => '1.3.6.1.4.1.3375.1.1.7.2.1.4',
    poolBitsin => '1.3.6.1.4.1.3375.1.1.7.2.1.5',
    poolBitsout => '1.3.6.1.4.1.3375.1.1.7.2.1.6',
    poolBitsinHi32 => '1.3.6.1.4.1.3375.1.1.7.2.1.7',
    poolBitsoutHi32 => '1.3.6.1.4.1.3375.1.1.7.2.1.8',
    poolPktsin => '1.3.6.1.4.1.3375.1.1.7.2.1.9',
    poolPktsout => '1.3.6.1.4.1.3375.1.1.7.2.1.10',
    poolPktsinHi32 => '1.3.6.1.4.1.3375.1.1.7.2.1.11',
    poolPktsoutHi32 => '1.3.6.1.4.1.3375.1.1.7.2.1.12',
    poolMaxConn => '1.3.6.1.4.1.3375.1.1.7.2.1.13',
    poolCurrentConn => '1.3.6.1.4.1.3375.1.1.7.2.1.14',
    poolTotalConn => '1.3.6.1.4.1.3375.1.1.7.2.1.15',
    poolPersistMode => '1.3.6.1.4.1.3375.1.1.7.2.1.16',
    poolSSLTimeout => '1.3.6.1.4.1.3375.1.1.7.2.1.17',
    poolSimpleTimeout => '1.3.6.1.4.1.3375.1.1.7.2.1.18',
    poolSimpleMask => '1.3.6.1.4.1.3375.1.1.7.2.1.19',
    poolStickyMask => '1.3.6.1.4.1.3375.1.1.7.2.1.20',
    poolCookieMode => '1.3.6.1.4.1.3375.1.1.7.2.1.21',
    poolCookieExpiration => '1.3.6.1.4.1.3375.1.1.7.2.1.22',
    poolCookieHashName => '1.3.6.1.4.1.3375.1.1.7.2.1.23',
    poolCookieHashOffset => '1.3.6.1.4.1.3375.1.1.7.2.1.24',
    poolCookieHashLength => '1.3.6.1.4.1.3375.1.1.7.2.1.25',
    poolMinActiveMembers => '1.3.6.1.4.1.3375.1.1.7.2.1.26',
    poolActiveMemberCount => '1.3.6.1.4.1.3375.1.1.7.2.1.27',
    poolPersistMirror => '1.3.6.1.4.1.3375.1.1.7.2.1.28',
    poolFallbackHost => '1.3.6.1.4.1.3375.1.1.7.2.1.29',
    poolMemberTable => '1.3.6.1.4.1.3375.1.1.8.2',
    poolMemberEntry => '1.3.6.1.4.1.3375.1.1.8.2.1',
    poolMemberPoolName => '1.3.6.1.4.1.3375.1.1.8.2.1.1',
    poolMemberIpAddress => '1.3.6.1.4.1.3375.1.1.8.2.1.2',
    poolMemberPort => '1.3.6.1.4.1.3375.1.1.8.2.1.3',
    poolMemberMaintenance => '1.3.6.1.4.1.3375.1.1.8.2.1.4',
    poolMemberRatio => '1.3.6.1.4.1.3375.1.1.8.2.1.5',
    poolMemberPriority => '1.3.6.1.4.1.3375.1.1.8.2.1.6',
    poolMemberWeight => '1.3.6.1.4.1.3375.1.1.8.2.1.7',
    poolMemberRipeness => '1.3.6.1.4.1.3375.1.1.8.2.1.8',
    poolMemberBitsin => '1.3.6.1.4.1.3375.1.1.8.2.1.9',
    poolMemberBitsout => '1.3.6.1.4.1.3375.1.1.8.2.1.10',
    poolMemberBitsinHi32 => '1.3.6.1.4.1.3375.1.1.8.2.1.11',
    poolMemberBitsoutHi32 => '1.3.6.1.4.1.3375.1.1.8.2.1.12',
    poolMemberPktsin => '1.3.6.1.4.1.3375.1.1.8.2.1.13',
    poolMemberPktsout => '1.3.6.1.4.1.3375.1.1.8.2.1.14',
    poolMemberPktsinHi32 => '1.3.6.1.4.1.3375.1.1.8.2.1.15',
    poolMemberPktsoutHi32 => '1.3.6.1.4.1.3375.1.1.8.2.1.16',
    poolMemberConnLimit => '1.3.6.1.4.1.3375.1.1.8.2.1.17',
    poolMemberMaxConn => '1.3.6.1.4.1.3375.1.1.8.2.1.18',
    poolMemberCurrentConn => '1.3.6.1.4.1.3375.1.1.8.2.1.19',
    poolMemberTotalConn => '1.3.6.1.4.1.3375.1.1.8.2.1.20',
    poolMemberStatus => '1.3.6.1.4.1.3375.1.1.8.2.1.21',
    poolMemberIpStatus => '1.3.6.1.4.1.3375.1.1.8.2.1.22',
  },
  'OLD-STATISTICS-MIB' => {
      hpSwitchCpuStat => '1.3.6.1.2.1.1.7.11.12.9.6.1.0',  # 'The CPU utilization in percent(%).'
  },
  'STATISTICS-MIB' => {
      hpSwitchCpuStat => '1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0',  # 'The CPU utilization in percent(%).'
  },
  'OLD-NETSWITCH-MIB' => {
      # hpLocalMemTotalBytes   1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5
      # hpLocalMemFreeBytes    1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6
      # hpLocalMemAllocBytes   1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7
      hpLocalMemTable => '1.3.6.1.2.1.1.7.11.12.1.2.1.1',
      hpLocalMemEntry => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1',
      hpLocalMemSlotIndex => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.1',
      hpLocalMemSlabCnt => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.2',
      hpLocalMemFreeSegCnt => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.3',
      hpLocalMemAllocSegCnt => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.4',
      hpLocalMemTotalBytes => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.5',
      hpLocalMemFreeBytes => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.6',
      hpLocalMemAllocBytes => '1.3.6.1.2.1.1.7.11.12.1.2.1.1.1.7',
      hpGlobalMemTable => '1.3.6.1.2.1.1.7.11.12.1.2.2.1',
      hpGlobalMemEntry => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1',
      hpGlobalMemSlotIndex => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.1',
      hpGlobalMemSlabCnt => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.2',
      hpGlobalMemFreeSegCnt => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.3',
      hpGlobalMemAllocSegCnt => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.4',
      hpGlobalMemTotalBytes => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.5',
      hpGlobalMemFreeBytes => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.6',
      hpGlobalMemAllocBytes => '1.3.6.1.2.1.1.7.11.12.1.2.2.1.1.7',
  },
  'NETSWITCH-MIB' => { #evt moderner
      hpLocalMemTable => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1',
      hpLocalMemEntry => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1',
      hpLocalMemSlotIndex => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.1',
      hpLocalMemSlabCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.2',
      hpLocalMemFreeSegCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.3',
      hpLocalMemAllocSegCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.4',
      hpLocalMemTotalBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5',
      hpLocalMemFreeBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6',
      hpLocalMemAllocBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7',
      hpGlobalMemTable => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1',
      hpGlobalMemEntry => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1',
      hpGlobalMemSlotIndex => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.1',
      hpGlobalMemSlabCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.2',
      hpGlobalMemFreeSegCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.3',
      hpGlobalMemAllocSegCnt => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.4',
      hpGlobalMemTotalBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.5',
      hpGlobalMemFreeBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.6',
      hpGlobalMemAllocBytes => '1.3.6.1.4.1.11.2.14.11.5.1.1.2.2.1.1.7',
  },
  'CHECKPOINT-MIB' => { #evt moderner
      'checkpoint' => '1.3.6.1.4.1.2620',
      'products' => '1.3.6.1.4.1.2620.1',
      'fw' => '1.3.6.1.4.1.2620.1.1',
      'vpn' => '1.3.6.1.4.1.2620.1.2',
      'fg' => '1.3.6.1.4.1.2620.1.3',
      'ha' => '1.3.6.1.4.1.2620.1.5',
      'svn' => '1.3.6.1.4.1.2620.1.6',
      'mngmt' => '1.3.6.1.4.1.2620.1.7',
      'wam' => '1.3.6.1.4.1.2620.1.8',
      'dtps' => '1.3.6.1.4.1.2620.1.9',
      'ls' => '1.3.6.1.4.1.2620.1.11',
      'fwPolicyStat' => '1.3.6.1.4.1.2620.1.1.25',
      'fwPerfStat' => '1.3.6.1.4.1.2620.1.1.26',
      'fwHmem' => '1.3.6.1.4.1.2620.1.1.26.1',
      'fwKmem' => '1.3.6.1.4.1.2620.1.1.26.2',
      'fwInspect' => '1.3.6.1.4.1.2620.1.1.26.3',
      'fwCookies' => '1.3.6.1.4.1.2620.1.1.26.4',
      'fwChains' => '1.3.6.1.4.1.2620.1.1.26.5',
      'fwFragments' => '1.3.6.1.4.1.2620.1.1.26.6',
      'fwUfp' => '1.3.6.1.4.1.2620.1.1.26.8',
      'fwSS' => '1.3.6.1.4.1.2620.1.1.26.9',
      'fwSS-http' => '1.3.6.1.4.1.2620.1.1.26.9.1',
      'fwSS-ftp' => '1.3.6.1.4.1.2620.1.1.26.9.2',
      'fwSS-telnet' => '1.3.6.1.4.1.2620.1.1.26.9.3',
      'fwSS-rlogin' => '1.3.6.1.4.1.2620.1.1.26.9.4',
      'fwSS-ufp' => '1.3.6.1.4.1.2620.1.1.26.9.5',
      'fwSS-smtp' => '1.3.6.1.4.1.2620.1.1.26.9.6',
      'fw' => '1.3.6.1.4.1.2620.1.1',
      'fwModuleState' => '1.3.6.1.4.1.2620.1.1.1.0',
      'fwFilterName' => '1.3.6.1.4.1.2620.1.1.2.0',
      'fwFilterDate' => '1.3.6.1.4.1.2620.1.1.3.0',
      'fwAccepted' => '1.3.6.1.4.1.2620.1.1.4.0',
      'fwRejected' => '1.3.6.1.4.1.2620.1.1.5.0',
      'fwDropped' => '1.3.6.1.4.1.2620.1.1.6.0',
      'fwLogged' => '1.3.6.1.4.1.2620.1.1.7.0',
      'fwMajor' => '1.3.6.1.4.1.2620.1.1.8.0',
      'fwMinor' => '1.3.6.1.4.1.2620.1.1.9.0',
      'fwProduct' => '1.3.6.1.4.1.2620.1.1.10.0',
      'fwEvent' => '1.3.6.1.4.1.2620.1.1.11.0',
      'fwProdName' => '1.3.6.1.4.1.2620.1.1.21.0',
      'fwVerMajor' => '1.3.6.1.4.1.2620.1.1.22.0',
      'fwVerMinor' => '1.3.6.1.4.1.2620.1.1.23.0',
      'fwKernelBuild' => '1.3.6.1.4.1.2620.1.1.24.0',
      'fwPolicyStat' => '1.3.6.1.4.1.2620.1.1.25',
      'fwPolicyName' => '1.3.6.1.4.1.2620.1.1.25.1.0',
      'fwInstallTime' => '1.3.6.1.4.1.2620.1.1.25.2.0',
      'fwNumConn' => '1.3.6.1.4.1.2620.1.1.25.3.0',
      'fwPeakNumConn' => '1.3.6.1.4.1.2620.1.1.25.4.0',
      'fwIfTable' => '1.3.6.1.4.1.2620.1.1.25.5',
      'fwIfEntry' => '1.3.6.1.4.1.2620.1.1.25.5.1',
      'fwIfIndex' => '1.3.6.1.4.1.2620.1.1.25.5.1.1',
      'fwIfName' => '1.3.6.1.4.1.2620.1.1.25.5.1.2',
      'fwAcceptPcktsIn' => '1.3.6.1.4.1.2620.1.1.25.5.1.5',
      'fwAcceptPcktsOut' => '1.3.6.1.4.1.2620.1.1.25.5.1.6',
      'fwAcceptBytesIn' => '1.3.6.1.4.1.2620.1.1.25.5.1.7',
      'fwAcceptBytesOut' => '1.3.6.1.4.1.2620.1.1.25.5.1.8',
      'fwDropPcktsIn' => '1.3.6.1.4.1.2620.1.1.25.5.1.9',
      'fwDropPcktsOut' => '1.3.6.1.4.1.2620.1.1.25.5.1.10',
      'fwRejectPcktsIn' => '1.3.6.1.4.1.2620.1.1.25.5.1.11',
      'fwRejectPcktsOut' => '1.3.6.1.4.1.2620.1.1.25.5.1.12',
      'fwLogIn' => '1.3.6.1.4.1.2620.1.1.25.5.1.13',
      'fwLogOut' => '1.3.6.1.4.1.2620.1.1.25.5.1.14',
      'fwHmem' => '1.3.6.1.4.1.2620.1.1.26.1',
      'fwHmem-block-size' => '1.3.6.1.4.1.2620.1.1.26.1.1.0',
      'fwHmem-requested-bytes' => '1.3.6.1.4.1.2620.1.1.26.1.2.0',
      'fwHmem-initial-allocated-bytes' => '1.3.6.1.4.1.2620.1.1.26.1.3.0',
      'fwHmem-initial-allocated-blocks' => '1.3.6.1.4.1.2620.1.1.26.1.4.0',
      'fwHmem-initial-allocated-pools' => '1.3.6.1.4.1.2620.1.1.26.1.5.0',
      'fwHmem-current-allocated-bytes' => '1.3.6.1.4.1.2620.1.1.26.1.6.0',
      'fwHmem-current-allocated-blocks' => '1.3.6.1.4.1.2620.1.1.26.1.7.0',
      'fwHmem-current-allocated-pools' => '1.3.6.1.4.1.2620.1.1.26.1.8.0',
      'fwHmem-maximum-bytes' => '1.3.6.1.4.1.2620.1.1.26.1.9.0',
      'fwHmem-maximum-pools' => '1.3.6.1.4.1.2620.1.1.26.1.10.0',
      'fwHmem-bytes-used' => '1.3.6.1.4.1.2620.1.1.26.1.11.0',
      'fwHmem-blocks-used' => '1.3.6.1.4.1.2620.1.1.26.1.12.0',
      'fwHmem-bytes-unused' => '1.3.6.1.4.1.2620.1.1.26.1.13.0',
      'fwHmem-blocks-unused' => '1.3.6.1.4.1.2620.1.1.26.1.14.0',
      'fwHmem-bytes-peak' => '1.3.6.1.4.1.2620.1.1.26.1.15.0',
      'fwHmem-blocks-peak' => '1.3.6.1.4.1.2620.1.1.26.1.16.0',
      'fwHmem-bytes-internal-use' => '1.3.6.1.4.1.2620.1.1.26.1.17.0',
      'fwHmem-number-of-items' => '1.3.6.1.4.1.2620.1.1.26.1.18.0',
      'fwHmem-alloc-operations' => '1.3.6.1.4.1.2620.1.1.26.1.19.0',
      'fwHmem-free-operations' => '1.3.6.1.4.1.2620.1.1.26.1.20.0',
      'fwHmem-failed-alloc' => '1.3.6.1.4.1.2620.1.1.26.1.21.0',
      'fwHmem-failed-free' => '1.3.6.1.4.1.2620.1.1.26.1.22.0',
      'fwKmem' => '1.3.6.1.4.1.2620.1.1.26.2',
      'fwKmem-system-physical-mem' => '1.3.6.1.4.1.2620.1.1.26.2.1.0',
      'fwKmem-available-physical-mem' => '1.3.6.1.4.1.2620.1.1.26.2.2.0',
      'fwKmem-aix-heap-size' => '1.3.6.1.4.1.2620.1.1.26.2.3.0',
      'fwKmem-bytes-used' => '1.3.6.1.4.1.2620.1.1.26.2.4.0',
      'fwKmem-blocking-bytes-used' => '1.3.6.1.4.1.2620.1.1.26.2.5.0',
      'fwKmem-non-blocking-bytes-used' => '1.3.6.1.4.1.2620.1.1.26.2.6.0',
      'fwKmem-bytes-unused' => '1.3.6.1.4.1.2620.1.1.26.2.7.0',
      'fwKmem-bytes-peak' => '1.3.6.1.4.1.2620.1.1.26.2.8.0',
      'fwKmem-blocking-bytes-peak' => '1.3.6.1.4.1.2620.1.1.26.2.9.0',
      'fwKmem-non-blocking-bytes-peak' => '1.3.6.1.4.1.2620.1.1.26.2.10.0',
      'fwKmem-bytes-internal-use' => '1.3.6.1.4.1.2620.1.1.26.2.11.0',
      'fwKmem-number-of-items' => '1.3.6.1.4.1.2620.1.1.26.2.12.0',
      'fwKmem-alloc-operations' => '1.3.6.1.4.1.2620.1.1.26.2.13.0',
      'fwKmem-free-operations' => '1.3.6.1.4.1.2620.1.1.26.2.14.0',
      'fwKmem-failed-alloc' => '1.3.6.1.4.1.2620.1.1.26.2.15.0',
      'fwKmem-failed-free' => '1.3.6.1.4.1.2620.1.1.26.2.16.0',
      'fwInspect' => '1.3.6.1.4.1.2620.1.1.26.3',
      'fwInspect-packets' => '1.3.6.1.4.1.2620.1.1.26.3.1.0',
      'fwInspect-operations' => '1.3.6.1.4.1.2620.1.1.26.3.2.0',
      'fwInspect-lookups' => '1.3.6.1.4.1.2620.1.1.26.3.3.0',
      'fwInspect-record' => '1.3.6.1.4.1.2620.1.1.26.3.4.0',
      'fwInspect-extract' => '1.3.6.1.4.1.2620.1.1.26.3.5.0',
      'fwCookies' => '1.3.6.1.4.1.2620.1.1.26.4',
      'fwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.1.0',
      'fwCookies-allocfwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.2.0',
      'fwCookies-freefwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.3.0',
      'fwCookies-dupfwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.4.0',
      'fwCookies-getfwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.5.0',
      'fwCookies-putfwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.6.0',
      'fwCookies-lenfwCookies-total' => '1.3.6.1.4.1.2620.1.1.26.4.7.0',
      'fwChains' => '1.3.6.1.4.1.2620.1.1.26.5',
      'fwChains-alloc' => '1.3.6.1.4.1.2620.1.1.26.5.1.0',
      'fwChains-free' => '1.3.6.1.4.1.2620.1.1.26.5.2.0',
      'fwFragments' => '1.3.6.1.4.1.2620.1.1.26.6',
      'fwFrag-fragments' => '1.3.6.1.4.1.2620.1.1.26.6.1.0',
      'fwFrag-expired' => '1.3.6.1.4.1.2620.1.1.26.6.2.0',
      'fwFrag-packets' => '1.3.6.1.4.1.2620.1.1.26.6.3.0',
      'fwUfp' => '1.3.6.1.4.1.2620.1.1.26.8',
      'fwUfpHitRatio' => '1.3.6.1.4.1.2620.1.1.26.8.1.0',
      'fwUfpInspected' => '1.3.6.1.4.1.2620.1.1.26.8.2.0',
      'fwUfpHits' => '1.3.6.1.4.1.2620.1.1.26.8.3.0',
      'fwSS-http' => '1.3.6.1.4.1.2620.1.1.26.9.1',
      'fwSS-http-pid' => '1.3.6.1.4.1.2620.1.1.26.9.1.1.0',
      'fwSS-http-proto' => '1.3.6.1.4.1.2620.1.1.26.9.1.2.0',
      'fwSS-http-port' => '1.3.6.1.4.1.2620.1.1.26.9.1.3.0',
      'fwSS-http-logical-port' => '1.3.6.1.4.1.2620.1.1.26.9.1.4.0',
      'fwSS-http-max-avail-socket' => '1.3.6.1.4.1.2620.1.1.26.9.1.5.0',
      'fwSS-http-socket-in-use-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.6.0',
      'fwSS-http-socket-in-use-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.7.0',
      'fwSS-http-socket-in-use-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.8.0',
      'fwSS-http-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.9.0',
      'fwSS-http-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.10.0',
      'fwSS-http-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.11.0',
      'fwSS-http-auth-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.12.0',
      'fwSS-http-auth-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.13.0',
      'fwSS-http-auth-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.14.0',
      'fwSS-http-accepted-sess' => '1.3.6.1.4.1.2620.1.1.26.9.1.15.0',
      'fwSS-http-rejected-sess' => '1.3.6.1.4.1.2620.1.1.26.9.1.16.0',
      'fwSS-http-auth-failures' => '1.3.6.1.4.1.2620.1.1.26.9.1.17.0',
      'fwSS-http-ops-cvp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.18.0',
      'fwSS-http-ops-cvp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.19.0',
      'fwSS-http-ops-cvp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.20.0',
      'fwSS-http-ops-cvp-rej-sess' => '1.3.6.1.4.1.2620.1.1.26.9.1.21.0',
      'fwSS-http-ssl-encryp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.22.0',
      'fwSS-http-ssl-encryp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.23.0',
      'fwSS-http-ssl-encryp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.24.0',
      'fwSS-http-transp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.25.0',
      'fwSS-http-transp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.26.0',
      'fwSS-http-transp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.27.0',
      'fwSS-http-proxied-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.28.0',
      'fwSS-http-proxied-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.29.0',
      'fwSS-http-proxied-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.30.0',
      'fwSS-http-tunneled-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.31.0',
      'fwSS-http-tunneled-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.32.0',
      'fwSS-http-tunneled-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.33.0',
      'fwSS-http-ftp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.1.34.0',
      'fwSS-http-ftp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.1.35.0',
      'fwSS-http-ftp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.1.36.0',
      'fwSS-http-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.1.37.0',
      'fwSS-http-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.1.38.0',
      'fwSS-ftp' => '1.3.6.1.4.1.2620.1.1.26.9.2',
      'fwSS-ftp-pid' => '1.3.6.1.4.1.2620.1.1.26.9.2.1.0',
      'fwSS-ftp-proto' => '1.3.6.1.4.1.2620.1.1.26.9.2.2.0',
      'fwSS-ftp-port' => '1.3.6.1.4.1.2620.1.1.26.9.2.3.0',
      'fwSS-ftp-logical-port' => '1.3.6.1.4.1.2620.1.1.26.9.2.4.0',
      'fwSS-ftp-max-avail-socket' => '1.3.6.1.4.1.2620.1.1.26.9.2.5.0',
      'fwSS-ftp-socket-in-use-max' => '1.3.6.1.4.1.2620.1.1.26.9.2.6.0',
      'fwSS-ftp-socket-in-use-curr' => '1.3.6.1.4.1.2620.1.1.26.9.2.7.0',
      'fwSS-ftp-socket-in-use-count' => '1.3.6.1.4.1.2620.1.1.26.9.2.8.0',
      'fwSS-ftp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.2.9.0',
      'fwSS-ftp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.2.10.0',
      'fwSS-ftp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.2.11.0',
      'fwSS-ftp-auth-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.2.12.0',
      'fwSS-ftp-auth-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.2.13.0',
      'fwSS-ftp-auth-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.2.14.0',
      'fwSS-ftp-accepted-sess' => '1.3.6.1.4.1.2620.1.1.26.9.2.15.0',
      'fwSS-ftp-rejected-sess' => '1.3.6.1.4.1.2620.1.1.26.9.2.16.0',
      'fwSS-ftp-auth-failures' => '1.3.6.1.4.1.2620.1.1.26.9.2.17.0',
      'fwSS-ftp-ops-cvp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.2.18.0',
      'fwSS-ftp-ops-cvp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.2.19.0',
      'fwSS-ftp-ops-cvp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.2.20.0',
      'fwSS-ftp-ops-cvp-rej-sess' => '1.3.6.1.4.1.2620.1.1.26.9.2.21.0',
      'fwSS-ftp-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.2.22.0',
      'fwSS-ftp-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.2.23.0',
      'fwSS-telnet' => '1.3.6.1.4.1.2620.1.1.26.9.3',
      'fwSS-telnet-pid' => '1.3.6.1.4.1.2620.1.1.26.9.3.1.0',
      'fwSS-telnet-proto' => '1.3.6.1.4.1.2620.1.1.26.9.3.2.0',
      'fwSS-telnet-port' => '1.3.6.1.4.1.2620.1.1.26.9.3.3.0',
      'fwSS-telnet-logical-port' => '1.3.6.1.4.1.2620.1.1.26.9.3.4.0',
      'fwSS-telnet-max-avail-socket' => '1.3.6.1.4.1.2620.1.1.26.9.3.5.0',
      'fwSS-telnet-socket-in-use-max' => '1.3.6.1.4.1.2620.1.1.26.9.3.6.0',
      'fwSS-telnet-socket-in-use-curr' => '1.3.6.1.4.1.2620.1.1.26.9.3.7.0',
      'fwSS-telnet-socket-in-use-count' => '1.3.6.1.4.1.2620.1.1.26.9.3.8.0',
      'fwSS-telnet-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.3.9.0',
      'fwSS-telnet-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.3.10.0',
      'fwSS-telnet-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.3.11.0',
      'fwSS-telnet-auth-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.3.12.0',
      'fwSS-telnet-auth-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.3.13.0',
      'fwSS-telnet-auth-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.3.14.0',
      'fwSS-telnet-accepted-sess' => '1.3.6.1.4.1.2620.1.1.26.9.3.15.0',
      'fwSS-telnet-rejected-sess' => '1.3.6.1.4.1.2620.1.1.26.9.3.16.0',
      'fwSS-telnet-auth-failures' => '1.3.6.1.4.1.2620.1.1.26.9.3.17.0',
      'fwSS-telnet-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.3.18.0',
      'fwSS-telnet-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.3.19.0',
      'fwSS-rlogin' => '1.3.6.1.4.1.2620.1.1.26.9.4',
      'fwSS-rlogin-pid' => '1.3.6.1.4.1.2620.1.1.26.9.4.1.0',
      'fwSS-rlogin-proto' => '1.3.6.1.4.1.2620.1.1.26.9.4.2.0',
      'fwSS-rlogin-port' => '1.3.6.1.4.1.2620.1.1.26.9.4.3.0',
      'fwSS-rlogin-logical-port' => '1.3.6.1.4.1.2620.1.1.26.9.4.4.0',
      'fwSS-rlogin-max-avail-socket' => '1.3.6.1.4.1.2620.1.1.26.9.4.5.0',
      'fwSS-rlogin-socket-in-use-max' => '1.3.6.1.4.1.2620.1.1.26.9.4.6.0',
      'fwSS-rlogin-socket-in-use-curr' => '1.3.6.1.4.1.2620.1.1.26.9.4.7.0',
      'fwSS-rlogin-socket-in-use-count' => '1.3.6.1.4.1.2620.1.1.26.9.4.8.0',
      'fwSS-rlogin-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.4.9.0',
      'fwSS-rlogin-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.4.10.0',
      'fwSS-rlogin-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.4.11.0',
      'fwSS-rlogin-auth-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.4.12.0',
      'fwSS-rlogin-auth-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.4.13.0',
      'fwSS-rlogin-auth-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.4.14.0',
      'fwSS-rlogin-accepted-sess' => '1.3.6.1.4.1.2620.1.1.26.9.4.15.0',
      'fwSS-rlogin-rejected-sess' => '1.3.6.1.4.1.2620.1.1.26.9.4.16.0',
      'fwSS-rlogin-auth-failures' => '1.3.6.1.4.1.2620.1.1.26.9.4.17.0',
      'fwSS-rlogin-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.4.18.0',
      'fwSS-rlogin-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.4.19.0',
      'fwSS-ufp' => '1.3.6.1.4.1.2620.1.1.26.9.5',
      'fwSS-ufp-ops-ufp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.5.1.0',
      'fwSS-ufp-ops-ufp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.5.2.0',
      'fwSS-ufp-ops-ufp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.5.3.0',
      'fwSS-ufp-ops-ufp-rej-sess' => '1.3.6.1.4.1.2620.1.1.26.9.5.4.0',
      'fwSS-ufp-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.5.5.0',
      'fwSS-ufp-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.5.6.0',
      'fwSS-smtp' => '1.3.6.1.4.1.2620.1.1.26.9.6',
      'fwSS-smtp-pid' => '1.3.6.1.4.1.2620.1.1.26.9.6.1.0',
      'fwSS-smtp-proto' => '1.3.6.1.4.1.2620.1.1.26.9.6.2.0',
      'fwSS-smtp-port' => '1.3.6.1.4.1.2620.1.1.26.9.6.3.0',
      'fwSS-smtp-logical-port' => '1.3.6.1.4.1.2620.1.1.26.9.6.4.0',
      'fwSS-smtp-max-avail-socket' => '1.3.6.1.4.1.2620.1.1.26.9.6.5.0',
      'fwSS-smtp-socket-in-use-max' => '1.3.6.1.4.1.2620.1.1.26.9.6.6.0',
      'fwSS-smtp-socket-in-use-curr' => '1.3.6.1.4.1.2620.1.1.26.9.6.7.0',
      'fwSS-smtp-socket-in-use-count' => '1.3.6.1.4.1.2620.1.1.26.9.6.8.0',
      'fwSS-smtp-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.6.9.0',
      'fwSS-smtp-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.6.10.0',
      'fwSS-smtp-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.6.11.0',
      'fwSS-smtp-auth-sess-max' => '1.3.6.1.4.1.2620.1.1.26.9.6.12.0',
      'fwSS-smtp-auth-sess-curr' => '1.3.6.1.4.1.2620.1.1.26.9.6.13.0',
      'fwSS-smtp-auth-sess-count' => '1.3.6.1.4.1.2620.1.1.26.9.6.14.0',
      'fwSS-smtp-accepted-sess' => '1.3.6.1.4.1.2620.1.1.26.9.6.15.0',
      'fwSS-smtp-rejected-sess' => '1.3.6.1.4.1.2620.1.1.26.9.6.16.0',
      'fwSS-smtp-auth-failures' => '1.3.6.1.4.1.2620.1.1.26.9.6.17.0',
      'fwSS-smtp-mail-max' => '1.3.6.1.4.1.2620.1.1.26.9.6.18.0',
      'fwSS-smtp-mail-curr' => '1.3.6.1.4.1.2620.1.1.26.9.6.19.0',
      'fwSS-smtp-mail-count' => '1.3.6.1.4.1.2620.1.1.26.9.6.20.0',
      'fwSS-smtp-outgoing-mail-max' => '1.3.6.1.4.1.2620.1.1.26.9.6.21.0',
      'fwSS-smtp-outgoing-mail-curr' => '1.3.6.1.4.1.2620.1.1.26.9.6.22.0',
      'fwSS-smtp-outgoing-mail-count' => '1.3.6.1.4.1.2620.1.1.26.9.6.23.0',
      'fwSS-smtp-max-mail-on-conn' => '1.3.6.1.4.1.2620.1.1.26.9.6.24.0',
      'fwSS-smtp-total-mails' => '1.3.6.1.4.1.2620.1.1.26.9.6.25.0',
      'fwSS-smtp-time-stamp' => '1.3.6.1.4.1.2620.1.1.26.9.6.26.0',
      'fwSS-smtp-is-alive' => '1.3.6.1.4.1.2620.1.1.26.9.6.27.0',
      'cpvGeneral' => '1.3.6.1.4.1.2620.1.2.4',
      'cpvIpsec' => '1.3.6.1.4.1.2620.1.2.5',
      'cpvFwz' => '1.3.6.1.4.1.2620.1.2.6',
      'cpvAccelerator' => '1.3.6.1.4.1.2620.1.2.8',
      'cpvIKE' => '1.3.6.1.4.1.2620.1.2.9',
      'cpvIPsec' => '1.3.6.1.4.1.2620.1.2.10',
      'cpvStatistics' => '1.3.6.1.4.1.2620.1.2.4.1',
      'cpvErrors' => '1.3.6.1.4.1.2620.1.2.4.2',
      'cpvSaStatistics' => '1.3.6.1.4.1.2620.1.2.5.2',
      'cpvSaErrors' => '1.3.6.1.4.1.2620.1.2.5.3',
      'cpvIpsecStatistics' => '1.3.6.1.4.1.2620.1.2.5.4',
      'cpvFwzStatistics' => '1.3.6.1.4.1.2620.1.2.6.1',
      'cpvFwzErrors' => '1.3.6.1.4.1.2620.1.2.6.2',
      'cpvHwAccelGeneral' => '1.3.6.1.4.1.2620.1.2.8.1',
      'cpvHwAccelStatistics' => '1.3.6.1.4.1.2620.1.2.8.2',
      'cpvIKEglobals' => '1.3.6.1.4.1.2620.1.2.9.1',
      'cpvIKEerrors' => '1.3.6.1.4.1.2620.1.2.9.2',
      'cpvIPsecNIC' => '1.3.6.1.4.1.2620.1.2.10.1',
      'vpn' => '1.3.6.1.4.1.2620.1.2',
      'cpvProdName' => '1.3.6.1.4.1.2620.1.2.1.0',
      'cpvVerMajor' => '1.3.6.1.4.1.2620.1.2.2.0',
      'cpvVerMinor' => '1.3.6.1.4.1.2620.1.2.3.0',
      'cpvStatistics' => '1.3.6.1.4.1.2620.1.2.4.1',
      'cpvEncPackets' => '1.3.6.1.4.1.2620.1.2.4.1.1.0',
      'cpvDecPackets' => '1.3.6.1.4.1.2620.1.2.4.1.2.0',
      'cpvErrors' => '1.3.6.1.4.1.2620.1.2.4.2',
      'cpvErrOut' => '1.3.6.1.4.1.2620.1.2.4.2.1.0',
      'cpvErrIn' => '1.3.6.1.4.1.2620.1.2.4.2.2.0',
      'cpvErrIke' => '1.3.6.1.4.1.2620.1.2.4.2.3.0',
      'cpvErrPolicy' => '1.3.6.1.4.1.2620.1.2.4.2.4.0',
      'cpvSaStatistics' => '1.3.6.1.4.1.2620.1.2.5.2',
      'cpvCurrEspSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.1.0',
      'cpvTotalEspSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.2.0',
      'cpvCurrEspSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.3.0',
      'cpvTotalEspSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.4.0',
      'cpvCurrAhSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.5.0',
      'cpvTotalAhSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.6.0',
      'cpvCurrAhSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.7.0',
      'cpvTotalAhSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.8.0',
      'cpvMaxConncurEspSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.9.0',
      'cpvMaxConncurEspSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.10.0',
      'cpvMaxConncurAhSAsIn' => '1.3.6.1.4.1.2620.1.2.5.2.11.0',
      'cpvMaxConncurAhSAsOut' => '1.3.6.1.4.1.2620.1.2.5.2.12.0',
      'cpvSaErrors' => '1.3.6.1.4.1.2620.1.2.5.3',
      'cpvSaDecrErr' => '1.3.6.1.4.1.2620.1.2.5.3.1.0',
      'cpvSaAuthErr' => '1.3.6.1.4.1.2620.1.2.5.3.2.0',
      'cpvSaReplayErr' => '1.3.6.1.4.1.2620.1.2.5.3.3.0',
      'cpvSaPolicyErr' => '1.3.6.1.4.1.2620.1.2.5.3.4.0',
      'cpvSaOtherErrIn' => '1.3.6.1.4.1.2620.1.2.5.3.5.0',
      'cpvSaOtherErrOut' => '1.3.6.1.4.1.2620.1.2.5.3.6.0',
      'cpvSaUnknownSpiErr' => '1.3.6.1.4.1.2620.1.2.5.3.7.0',
      'cpvIpsecStatistics' => '1.3.6.1.4.1.2620.1.2.5.4',
      'cpvIpsecUdpEspEncPkts' => '1.3.6.1.4.1.2620.1.2.5.4.1.0',
      'cpvIpsecUdpEspDecPkts' => '1.3.6.1.4.1.2620.1.2.5.4.2.0',
      'cpvIpsecAhEncPkts' => '1.3.6.1.4.1.2620.1.2.5.4.3.0',
      'cpvIpsecAhDecPkts' => '1.3.6.1.4.1.2620.1.2.5.4.4.0',
      'cpvIpsecEspEncPkts' => '1.3.6.1.4.1.2620.1.2.5.4.5.0',
      'cpvIpsecEspDecPkts' => '1.3.6.1.4.1.2620.1.2.5.4.6.0',
      'cpvIpsecDecomprBytesBefore' => '1.3.6.1.4.1.2620.1.2.5.4.7.0',
      'cpvIpsecDecomprBytesAfter' => '1.3.6.1.4.1.2620.1.2.5.4.8.0',
      'cpvIpsecDecomprOverhead' => '1.3.6.1.4.1.2620.1.2.5.4.9.0',
      'cpvIpsecDecomprPkts' => '1.3.6.1.4.1.2620.1.2.5.4.10.0',
      'cpvIpsecDecomprErr' => '1.3.6.1.4.1.2620.1.2.5.4.11.0',
      'cpvIpsecComprBytesBefore' => '1.3.6.1.4.1.2620.1.2.5.4.12.0',
      'cpvIpsecComprBytesAfter' => '1.3.6.1.4.1.2620.1.2.5.4.13.0',
      'cpvIpsecComprOverhead' => '1.3.6.1.4.1.2620.1.2.5.4.14.0',
      'cpvIpsecNonCompressibleBytes' => '1.3.6.1.4.1.2620.1.2.5.4.15.0',
      'cpvIpsecCompressiblePkts' => '1.3.6.1.4.1.2620.1.2.5.4.16.0',
      'cpvIpsecNonCompressiblePkts' => '1.3.6.1.4.1.2620.1.2.5.4.17.0',
      'cpvIpsecComprErrors' => '1.3.6.1.4.1.2620.1.2.5.4.18.0',
      'cpvIpsecEspEncBytes' => '1.3.6.1.4.1.2620.1.2.5.4.19.0',
      'cpvIpsecEspDecBytes' => '1.3.6.1.4.1.2620.1.2.5.4.20.0',
      'cpvFwzStatistics' => '1.3.6.1.4.1.2620.1.2.6.1',
      'cpvFwzEncapsEncPkts' => '1.3.6.1.4.1.2620.1.2.6.1.1.0',
      'cpvFwzEncapsDecPkts' => '1.3.6.1.4.1.2620.1.2.6.1.2.0',
      'cpvFwzEncPkts' => '1.3.6.1.4.1.2620.1.2.6.1.3.0',
      'cpvFwzDecPkts' => '1.3.6.1.4.1.2620.1.2.6.1.4.0',
      'cpvFwzErrors' => '1.3.6.1.4.1.2620.1.2.6.2',
      'cpvFwzEncapsEncErrs' => '1.3.6.1.4.1.2620.1.2.6.2.1.0',
      'cpvFwzEncapsDecErrs' => '1.3.6.1.4.1.2620.1.2.6.2.2.0',
      'cpvFwzEncErrs' => '1.3.6.1.4.1.2620.1.2.6.2.3.0',
      'cpvFwzDecErrs' => '1.3.6.1.4.1.2620.1.2.6.2.4.0',
      'cpvHwAccelGeneral' => '1.3.6.1.4.1.2620.1.2.8.1',
      'cpvHwAccelVendor' => '1.3.6.1.4.1.2620.1.2.8.1.1.0',
      'cpvHwAccelStatus' => '1.3.6.1.4.1.2620.1.2.8.1.2.0',
      'cpvHwAccelDriverMajorVer' => '1.3.6.1.4.1.2620.1.2.8.1.3.0',
      'cpvHwAccelDriverMinorVer' => '1.3.6.1.4.1.2620.1.2.8.1.4.0',
      'cpvHwAccelStatistics' => '1.3.6.1.4.1.2620.1.2.8.2',
      'cpvHwAccelEspEncPkts' => '1.3.6.1.4.1.2620.1.2.8.2.1.0',
      'cpvHwAccelEspDecPkts' => '1.3.6.1.4.1.2620.1.2.8.2.2.0',
      'cpvHwAccelEspEncBytes' => '1.3.6.1.4.1.2620.1.2.8.2.3.0',
      'cpvHwAccelEspDecBytes' => '1.3.6.1.4.1.2620.1.2.8.2.4.0',
      'cpvHwAccelAhEncPkts' => '1.3.6.1.4.1.2620.1.2.8.2.5.0',
      'cpvHwAccelAhDecPkts' => '1.3.6.1.4.1.2620.1.2.8.2.6.0',
      'cpvHwAccelAhEncBytes' => '1.3.6.1.4.1.2620.1.2.8.2.7.0',
      'cpvHwAccelAhDecBytes' => '1.3.6.1.4.1.2620.1.2.8.2.8.0',
      'cpvIKEglobals' => '1.3.6.1.4.1.2620.1.2.9.1',
      'cpvIKECurrSAs' => '1.3.6.1.4.1.2620.1.2.9.1.1.0',
      'cpvIKECurrInitSAs' => '1.3.6.1.4.1.2620.1.2.9.1.2.0',
      'cpvIKECurrRespSAs' => '1.3.6.1.4.1.2620.1.2.9.1.3.0',
      'cpvIKETotalSAs' => '1.3.6.1.4.1.2620.1.2.9.1.4.0',
      'cpvIKETotalInitSAs' => '1.3.6.1.4.1.2620.1.2.9.1.5.0',
      'cpvIKETotalRespSAs' => '1.3.6.1.4.1.2620.1.2.9.1.6.0',
      'cpvIKETotalSAsAttempts' => '1.3.6.1.4.1.2620.1.2.9.1.7.0',
      'cpvIKETotalSAsInitAttempts' => '1.3.6.1.4.1.2620.1.2.9.1.8.0',
      'cpvIKETotalSAsRespAttempts' => '1.3.6.1.4.1.2620.1.2.9.1.9.0',
      'cpvIKEMaxConncurSAs' => '1.3.6.1.4.1.2620.1.2.9.1.10.0',
      'cpvIKEMaxConncurInitSAs' => '1.3.6.1.4.1.2620.1.2.9.1.11.0',
      'cpvIKEMaxConncurRespSAs' => '1.3.6.1.4.1.2620.1.2.9.1.12.0',
      'cpvIKEerrors' => '1.3.6.1.4.1.2620.1.2.9.2',
      'cpvIKETotalFailuresInit' => '1.3.6.1.4.1.2620.1.2.9.2.1.0',
      'cpvIKENoResp' => '1.3.6.1.4.1.2620.1.2.9.2.2.0',
      'cpvIKETotalFailuresResp' => '1.3.6.1.4.1.2620.1.2.9.2.3.0',
      'cpvIPsecNIC' => '1.3.6.1.4.1.2620.1.2.10.1',
      'cpvIPsecNICsNum' => '1.3.6.1.4.1.2620.1.2.10.1.1.0',
      'cpvIPsecNICTotalDownLoadedSAs' => '1.3.6.1.4.1.2620.1.2.10.1.2.0',
      'cpvIPsecNICCurrDownLoadedSAs' => '1.3.6.1.4.1.2620.1.2.10.1.3.0',
      'cpvIPsecNICDecrBytes' => '1.3.6.1.4.1.2620.1.2.10.1.4.0',
      'cpvIPsecNICEncrBytes' => '1.3.6.1.4.1.2620.1.2.10.1.5.0',
      'cpvIPsecNICDecrPackets' => '1.3.6.1.4.1.2620.1.2.10.1.6.0',
      'cpvIPsecNICEncrPackets' => '1.3.6.1.4.1.2620.1.2.10.1.7.0',
      'vpn' => '1.3.6.1.4.1.2620.1.2',
      'cpvTnlMon' => '1.3.6.1.4.1.2620.1.2.11',
      'cpvTnlMonEntry' => '1.3.6.1.4.1.2620.1.2.11.1',
      'cpvTnlMonAddr' => '1.3.6.1.4.1.2620.1.2.11.1.1',
      'cpvTnlMonStatus' => '1.3.6.1.4.1.2620.1.2.11.1.2',
      'cpvTnlMonCurrAddr' => '1.3.6.1.4.1.2620.1.2.11.1.3',
      'fg' => '1.3.6.1.4.1.2620.1.3',
      'fgProdName' => '1.3.6.1.4.1.2620.1.3.1.0',
      'fgVerMajor' => '1.3.6.1.4.1.2620.1.3.2.0',
      'fgVerMinor' => '1.3.6.1.4.1.2620.1.3.3.0',
      'fgVersionString' => '1.3.6.1.4.1.2620.1.3.4.0',
      'fgModuleKernelBuild' => '1.3.6.1.4.1.2620.1.3.5.0',
      'fgStrPolicyName' => '1.3.6.1.4.1.2620.1.3.6.0',
      'fgInstallTime' => '1.3.6.1.4.1.2620.1.3.7.0',
      'fgNumInterfaces' => '1.3.6.1.4.1.2620.1.3.8.0',
      'fgIfTable' => '1.3.6.1.4.1.2620.1.3.9',
      'fgIfEntry' => '1.3.6.1.4.1.2620.1.3.9.1',
      'fgIfIndex' => '1.3.6.1.4.1.2620.1.3.9.1.1',
      'fgIfName' => '1.3.6.1.4.1.2620.1.3.9.1.2',
      'fgPolicyName' => '1.3.6.1.4.1.2620.1.3.9.1.3',
      'fgRateLimitIn' => '1.3.6.1.4.1.2620.1.3.9.1.4',
      'fgRateLimitOut' => '1.3.6.1.4.1.2620.1.3.9.1.5',
      'fgAvrRateIn' => '1.3.6.1.4.1.2620.1.3.9.1.6',
      'fgAvrRateOut' => '1.3.6.1.4.1.2620.1.3.9.1.7',
      'fgRetransPcktsIn' => '1.3.6.1.4.1.2620.1.3.9.1.8',
      'fgRetransPcktsOut' => '1.3.6.1.4.1.2620.1.3.9.1.9',
      'fgPendPcktsIn' => '1.3.6.1.4.1.2620.1.3.9.1.10',
      'fgPendPcktsOut' => '1.3.6.1.4.1.2620.1.3.9.1.11',
      'fgPendBytesIn' => '1.3.6.1.4.1.2620.1.3.9.1.12',
      'fgPendBytesOut' => '1.3.6.1.4.1.2620.1.3.9.1.13',
      'fgNumConnIn' => '1.3.6.1.4.1.2620.1.3.9.1.14',
      'fgNumConnOut' => '1.3.6.1.4.1.2620.1.3.9.1.15',
      'ha' => '1.3.6.1.4.1.2620.1.5',
      'haProdName' => '1.3.6.1.4.1.2620.1.5.1.0',
      'haInstalled' => '1.3.6.1.4.1.2620.1.5.2.0',
      'haVerMajor' => '1.3.6.1.4.1.2620.1.5.3.0',
      'haVerMinor' => '1.3.6.1.4.1.2620.1.5.4.0',
      'haStarted' => '1.3.6.1.4.1.2620.1.5.5.0',
      'haState' => '1.3.6.1.4.1.2620.1.5.6.0',
      'haBlockState' => '1.3.6.1.4.1.2620.1.5.7.0',
      'haIdentifier' => '1.3.6.1.4.1.2620.1.5.8.0',
      'haProtoVersion' => '1.3.6.1.4.1.2620.1.5.10.0',
      'haWorkMode' => '1.3.6.1.4.1.2620.1.5.11.0',
      'haVersionSting' => '1.3.6.1.4.1.2620.1.5.14.0',
      'haStatCode' => '1.3.6.1.4.1.2620.1.5.101.0',
      'haStatShort' => '1.3.6.1.4.1.2620.1.5.102.0',
      'haStatLong' => '1.3.6.1.4.1.2620.1.5.103.0',
      'haServicePack' => '1.3.6.1.4.1.2620.1.5.999.0',
      'haIfTable' => '1.3.6.1.4.1.2620.1.5.12',
      'haIfEntry' => '1.3.6.1.4.1.2620.1.5.12.1',
      'haIfIndex' => '1.3.6.1.4.1.2620.1.5.12.1.1',
      'haIfName' => '1.3.6.1.4.1.2620.1.5.12.1.2',
      'haIP' => '1.3.6.1.4.1.2620.1.5.12.1.3',
      'haStatus' => '1.3.6.1.4.1.2620.1.5.12.1.4',
      'haVerified' => '1.3.6.1.4.1.2620.1.5.12.1.5',
      'haTrusted' => '1.3.6.1.4.1.2620.1.5.12.1.6',
      'haShared' => '1.3.6.1.4.1.2620.1.5.12.1.7',
      'haProblemTable' => '1.3.6.1.4.1.2620.1.5.13',
      'haProblemEntry' => '1.3.6.1.4.1.2620.1.5.13.1',
      'haProblemIndex' => '1.3.6.1.4.1.2620.1.5.13.1.1',
      'haProblemName' => '1.3.6.1.4.1.2620.1.5.13.1.2',
      'haProblemStatus' => '1.3.6.1.4.1.2620.1.5.13.1.3',
      'haProblemPriority' => '1.3.6.1.4.1.2620.1.5.13.1.4',
      'haProblemVerified' => '1.3.6.1.4.1.2620.1.5.13.1.5',
      'haProblemDescr' => '1.3.6.1.4.1.2620.1.5.13.1.6',
      'svnInfo' => '1.3.6.1.4.1.2620.1.6.4',
      'svnOSInfo' => '1.3.6.1.4.1.2620.1.6.5',
      'svnPerf' => '1.3.6.1.4.1.2620.1.6.7',
      'svnMem' => '1.3.6.1.4.1.2620.1.6.7.1',
      'svnProc' => '1.3.6.1.4.1.2620.1.6.7.2',
      'svnDisk' => '1.3.6.1.4.1.2620.1.6.7.3',
      'svnMem64' => '1.3.6.1.4.1.2620.1.6.7.4',
      'svn' => '1.3.6.1.4.1.2620.1.6',
      'svnProdName' => '1.3.6.1.4.1.2620.1.6.1.0',
      'svnProdVerMajor' => '1.3.6.1.4.1.2620.1.6.2.0',
      'svnProdVerMinor' => '1.3.6.1.4.1.2620.1.6.3.0',
      'svnInfo' => '1.3.6.1.4.1.2620.1.6.4',
      'svnVersion' => '1.3.6.1.4.1.2620.1.6.4.1.0',
      'svnBuild' => '1.3.6.1.4.1.2620.1.6.4.2.0',
      'svnOSInfo' => '1.3.6.1.4.1.2620.1.6.5',
      'osName' => '1.3.6.1.4.1.2620.1.6.5.1.0',
      'osMajorVer' => '1.3.6.1.4.1.2620.1.6.5.2.0',
      'osMinorVer' => '1.3.6.1.4.1.2620.1.6.5.3.0',
      'osBuildNum' => '1.3.6.1.4.1.2620.1.6.5.4.0',
      'osSPmajor' => '1.3.6.1.4.1.2620.1.6.5.5.0',
      'osSPminor' => '1.3.6.1.4.1.2620.1.6.5.6.0',
      'osVersionLevel' => '1.3.6.1.4.1.2620.1.6.5.7.0',
      'svnMem' => '1.3.6.1.4.1.2620.1.6.7.1',
      'memTotalVirtual' => '1.3.6.1.4.1.2620.1.6.7.1.1.0',
      'memActiveVirtual' => '1.3.6.1.4.1.2620.1.6.7.1.2.0',
      'memTotalReal' => '1.3.6.1.4.1.2620.1.6.7.1.3.0',
      'memActiveReal' => '1.3.6.1.4.1.2620.1.6.7.1.4.0',
      'memFreeReal' => '1.3.6.1.4.1.2620.1.6.7.1.5.0',
      'memSwapsSec' => '1.3.6.1.4.1.2620.1.6.7.1.6.0',
      'memDiskTransfers' => '1.3.6.1.4.1.2620.1.6.7.1.7.0',
      'svnProc' => '1.3.6.1.4.1.2620.1.6.7.2',
      'procUsrTime' => '1.3.6.1.4.1.2620.1.6.7.2.1.0',
      'procSysTime' => '1.3.6.1.4.1.2620.1.6.7.2.2.0',
      'procIdleTime' => '1.3.6.1.4.1.2620.1.6.7.2.3.0',
      'procUsage' => '1.3.6.1.4.1.2620.1.6.7.2.4.0',
      'procQueue' => '1.3.6.1.4.1.2620.1.6.7.2.5.0',
      'procInterrupts' => '1.3.6.1.4.1.2620.1.6.7.2.6.0',
      'procNum' => '1.3.6.1.4.1.2620.1.6.7.2.7.0',
      'svnDisk' => '1.3.6.1.4.1.2620.1.6.7.3',
      'diskTime' => '1.3.6.1.4.1.2620.1.6.7.3.1.0',
      'diskQueue' => '1.3.6.1.4.1.2620.1.6.7.3.2.0',
      'diskPercent' => '1.3.6.1.4.1.2620.1.6.7.3.3.0',
      'diskFreeTotal' => '1.3.6.1.4.1.2620.1.6.7.3.4.0',
      'diskFreeAvail' => '1.3.6.1.4.1.2620.1.6.7.3.5.0',
      'diskTotal' => '1.3.6.1.4.1.2620.1.6.7.3.6.0',
      'svnMem64' => '1.3.6.1.4.1.2620.1.6.7.4',
      'memTotalVirtual64' => '1.3.6.1.4.1.2620.1.6.7.4.1.0',
      'memActiveVirtual64' => '1.3.6.1.4.1.2620.1.6.7.4.2.0',
      'memTotalReal64' => '1.3.6.1.4.1.2620.1.6.7.4.3.0',
      'memActiveReal64' => '1.3.6.1.4.1.2620.1.6.7.4.4.0',
      'memFreeReal64' => '1.3.6.1.4.1.2620.1.6.7.4.5.0',
      'memSwapsSec64' => '1.3.6.1.4.1.2620.1.6.7.4.6.0',
      'memDiskTransfers64' => '1.3.6.1.4.1.2620.1.6.7.4.7.0',
      'svn' => '1.3.6.1.4.1.2620.1.6',
      'routingTable' => '1.3.6.1.4.1.2620.1.6.6',
      'routingEntry' => '1.3.6.1.4.1.2620.1.6.6.1',
      'routingIndex' => '1.3.6.1.4.1.2620.1.6.6.1.1',
      'routingDest' => '1.3.6.1.4.1.2620.1.6.6.1.2',
      'routingMask' => '1.3.6.1.4.1.2620.1.6.6.1.3',
      'routingGatweway' => '1.3.6.1.4.1.2620.1.6.6.1.4',
      'routingIntrfName' => '1.3.6.1.4.1.2620.1.6.6.1.5',
      'svnStatCode' => '1.3.6.1.4.1.2620.1.6.101.0',
      'svnStatShortDescr' => '1.3.6.1.4.1.2620.1.6.102.0',
      'svnStatLongDescr' => '1.3.6.1.4.1.2620.1.6.103.0',
      'svnServicePack' => '1.3.6.1.4.1.2620.1.6.999.0',
      'mngmt' => '1.3.6.1.4.1.2620.1.7',
      'mgProdName' => '1.3.6.1.4.1.2620.1.7.1.0',
      'mgVerMajor' => '1.3.6.1.4.1.2620.1.7.2.0',
      'mgVerMinor' => '1.3.6.1.4.1.2620.1.7.3.0',
      'mgBuildNumber' => '1.3.6.1.4.1.2620.1.7.4.0',
      'mgActiveStatus' => '1.3.6.1.4.1.2620.1.7.5.0',
      'mgFwmIsAlive' => '1.3.6.1.4.1.2620.1.7.6.0',
      'mgConnectedClientsTable' => '1.3.6.1.4.1.2620.1.7.7',
      'mgConnectedClientsEntry' => '1.3.6.1.4.1.2620.1.7.7.1',
      'mgIndex' => '1.3.6.1.4.1.2620.1.7.7.1.1',
      'mgClientName' => '1.3.6.1.4.1.2620.1.7.7.1.2',
      'mgClientHost' => '1.3.6.1.4.1.2620.1.7.7.1.3',
      'mgClientDbLock' => '1.3.6.1.4.1.2620.1.7.7.1.4',
      'mgApplicationType' => '1.3.6.1.4.1.2620.1.7.7.1.5',
      'mgStatCode' => '1.3.6.1.4.1.2620.1.7.101.0',
      'mgStatShortDescr' => '1.3.6.1.4.1.2620.1.7.102.0',
      'mgStatLongDescr' => '1.3.6.1.4.1.2620.1.7.103.0',
      'wamPluginPerformance' => '1.3.6.1.4.1.2620.1.8.6',
      'wamPolicy' => '1.3.6.1.4.1.2620.1.8.7',
      'wamUagQueries' => '1.3.6.1.4.1.2620.1.8.8',
      'wamGlobalPerformance' => '1.3.6.1.4.1.2620.1.8.9',
      'wam' => '1.3.6.1.4.1.2620.1.8',
      'wamProdName' => '1.3.6.1.4.1.2620.1.8.1.0',
      'wamVerMajor' => '1.3.6.1.4.1.2620.1.8.2.0',
      'wamVerMinor' => '1.3.6.1.4.1.2620.1.8.3.0',
      'wamState' => '1.3.6.1.4.1.2620.1.8.4.0',
      'wamName' => '1.3.6.1.4.1.2620.1.8.5.0',
      'wamStatCode' => '1.3.6.1.4.1.2620.1.8.101.0',
      'wamStatShortDescr' => '1.3.6.1.4.1.2620.1.8.102.0',
      'wamStatLongDescr' => '1.3.6.1.4.1.2620.1.8.103.0',
      'wamPluginPerformance' => '1.3.6.1.4.1.2620.1.8.6',
      'wamAcceptReq' => '1.3.6.1.4.1.2620.1.8.6.1.0',
      'wamRejectReq' => '1.3.6.1.4.1.2620.1.8.6.2.0',
      'wamPolicy' => '1.3.6.1.4.1.2620.1.8.7',
      'wamPolicyName' => '1.3.6.1.4.1.2620.1.8.7.1.0',
      'wamPolicyUpdate' => '1.3.6.1.4.1.2620.1.8.7.2.0',
      'wamUagQueries' => '1.3.6.1.4.1.2620.1.8.8',
      'wamUagHost' => '1.3.6.1.4.1.2620.1.8.8.1.0',
      'wamUagIp' => '1.3.6.1.4.1.2620.1.8.8.2.0',
      'wamUagPort' => '1.3.6.1.4.1.2620.1.8.8.3.0',
      'wamUagNoQueries' => '1.3.6.1.4.1.2620.1.8.8.4.0',
      'wamUagLastQuery' => '1.3.6.1.4.1.2620.1.8.8.5.0',
      'wamGlobalPerformance' => '1.3.6.1.4.1.2620.1.8.9',
      'wamOpenSessions' => '1.3.6.1.4.1.2620.1.8.9.1.0',
      'wamLastSession' => '1.3.6.1.4.1.2620.1.8.9.2.0',
      'dtps' => '1.3.6.1.4.1.2620.1.9',
      'dtpsProdName' => '1.3.6.1.4.1.2620.1.9.1.0',
      'dtpsVerMajor' => '1.3.6.1.4.1.2620.1.9.2.0',
      'dtpsVerMinor' => '1.3.6.1.4.1.2620.1.9.3.0',
      'dtpsLicensedUsers' => '1.3.6.1.4.1.2620.1.9.4.0',
      'dtpsConnectedUsers' => '1.3.6.1.4.1.2620.1.9.5.0',
      'dtpsStatCode' => '1.3.6.1.4.1.2620.1.9.101.0',
      'dtpsStatShortDescr' => '1.3.6.1.4.1.2620.1.9.102.0',
      'dtpsStatLongDescr' => '1.3.6.1.4.1.2620.1.9.103.0',
      'ls' => '1.3.6.1.4.1.2620.1.11',
      'lsProdName' => '1.3.6.1.4.1.2620.1.11.1.0',
      'lsVerMajor' => '1.3.6.1.4.1.2620.1.11.2.0',
      'lsVerMinor' => '1.3.6.1.4.1.2620.1.11.3.0',
      'lsBuildNumber' => '1.3.6.1.4.1.2620.1.11.4.0',
      'lsFwmIsAlive' => '1.3.6.1.4.1.2620.1.11.5.0',
      'lsStatCode' => '1.3.6.1.4.1.2620.1.11.101.0',
      'lsStatShortDescr' => '1.3.6.1.4.1.2620.1.11.102.0',
      'lsStatLongDescr' => '1.3.6.1.4.1.2620.1.11.103.0',
      'lsConnectedClientsTable' => '1.3.6.1.4.1.2620.1.11.7',
      'lsConnectedClientsEntry' => '1.3.6.1.4.1.2620.1.11.7.1',
      'lsIndex' => '1.3.6.1.4.1.2620.1.11.7.1.1',
      'lsClientName' => '1.3.6.1.4.1.2620.1.11.7.1.2',
      'lsClientHost' => '1.3.6.1.4.1.2620.1.11.7.1.3',
      'lsClientDbLock' => '1.3.6.1.4.1.2620.1.11.7.1.4',
      'lsApplicationType' => '1.3.6.1.4.1.2620.1.11.7.1.5',
      # undocumented?
      # https://sc1.checkpoint.com/documents/R76/CP_R76_Splat_AdminGuide/51555.htm
      'volumesTable' => '1.3.6.1.4.1.2620.1.6.7.7.1',
      'volumesEntry' => '1.3.6.1.4.1.2620.1.6.7.7.1.1',
      'volumesIndex' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.1',
      'volumesVolumeID' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.2',
      'volumesVolumeType' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.3',
      'volumesNumberOfDisks' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.4',
      'volumesVolumeSize' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.5',
      'volumesVolumeState' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.6',
      'volumesVolumeStateDefinition' => {
          0 => 'optimal',
          1 => 'degraded',
          2 => 'failed',
      },
      'volumesVolumeFlags' => '1.3.6.1.4.1.2620.1.6.7.7.1.1.7',
      'volumesVolumeFlagsDefinition' => {
          0 => 'enabled',
          1 => 'quiesced',
          2 => 'resync_in_progress',
          3 => 'volume_inactive',
      },
      'disksTable' => '1.3.6.1.4.1.2620.1.6.7.7.2',
      'disksEntry' => '1.3.6.1.4.1.2620.1.6.7.7.2.1',
      'disksIndex' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.1',
      'disksVolumeID' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.2',
      'disksScsiID' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.3',
      'disksDiskNumber' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.4',
      'disksDiskNumber' => {
          0 => 'upper',
          1 => 'lower',
      },
      'disksVendor' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.5',
      'disksProductID' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.6',
      'disksRevision' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.7',
      'disksSize' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.8',
      'disksState' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.9',
      'disksStateDefinition' => {
          0 => 'online',
          1 => 'missing',
          2 => 'not_compatible',
          3 => 'failed',
          4 => 'initializing',
          5 => 'offline_requested',
          6 => 'failed_requested',
          7 => 'other_offline',
      },
      'disksFlags' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.10',
      'disksFlagsDefinition' => {
          0 => 'out_of_sync',
          1 => 'quiesced',
          16 => 'ok',
      },
      'disksSyncState' => '1.3.6.1.4.1.2620.1.6.7.7.2.1.11',
      'sensorsTemperatureTable' => '1.3.6.1.4.1.2620.1.6.7.8.1',
      'sensorsTemperatureEntry' => '1.3.6.1.4.1.2620.1.6.7.8.1.1',
      'sensorsTemperatureIndex' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.1',
      'sensorsTemperatureName' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.2',
      'sensorsTemperatureValue' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.3',
      'sensorsTemperatureUOM' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.4',
      'sensorsTemperatureType' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.5',
      'sensorsTemperatureStatus' => '1.3.6.1.4.1.2620.1.6.7.8.1.1.6',
      'sensorsTemperatureStatusDefinition' => {
          0 => 'normal', # In normal range
          1 => 'abnormal', # Out of normal range
          2 => 'unknown', # Reading error
      },

      'sensorsFanTable' => '1.3.6.1.4.1.2620.1.6.7.8.2',
      'sensorsFanEntry' => '1.3.6.1.4.1.2620.1.6.7.8.2.1',
      'sensorsFanIndex' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.1',
      'sensorsFanName' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.2',
      'sensorsFanValue' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.3',
      'sensorsFanUOM' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.4',
      'sensorsFanType' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.5',
      'sensorsFanStatus' => '1.3.6.1.4.1.2620.1.6.7.8.2.1.6',
      'sensorsFanStatusDefinition' => {
          0 => 'normal',
          1 => 'abnormal',
          2 => 'unknown',
      },

      'sensorsVoltageTable' => '1.3.6.1.4.1.2620.1.6.7.8.3',
      'sensorsVoltageEntry' => '1.3.6.1.4.1.2620.1.6.7.8.3.1',
      'sensorsVoltageIndex' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.1',
      'sensorsVoltageName' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.2',
      'sensorsVoltageValue' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.3',
      'sensorsVoltageUOM' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.4',
      'sensorsVoltageType' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.5',
      'sensorsVoltageStatus' => '1.3.6.1.4.1.2620.1.6.7.8.3.1.6',
      'sensorsVoltageStatusDefinition' => {
          0 => 'normal',
          1 => 'abnormal',
          2 => 'unknown',
      },
  },
  'CLAVISTER-MIB' => {
      'clvSystem' => '1.3.6.1.4.1.5089.1.2.1',
      'clvSysCpuLoad' => '1.3.6.1.4.1.5089.1.2.1.1.0',
      'clvHWSensorTable' => '1.3.6.1.4.1.5089.1.2.1.11',
      'clvHWSensorEntry' => '1.3.6.1.4.1.5089.1.2.1.11.1',
      'clvHWSensorIndex' => '1.3.6.1.4.1.5089.1.2.1.11.1.1',
      'clvHWSensorName' => '1.3.6.1.4.1.5089.1.2.1.11.1.2',
      'clvHWSensorValue' => '1.3.6.1.4.1.5089.1.2.1.11.1.3',
      'clvHWSensorUnit' => '1.3.6.1.4.1.5089.1.2.1.11.1.4',
      'clvSysMemUsage' => '1.3.6.1.4.1.5089.1.2.1.12.0',
  },
  'NETSCREEN-RESOURCE-MIB' => {
      nsResCpuAvg => '1.3.6.1.4.1.3224.16.1.1.0',
      nsResCpuLast15Min => '1.3.6.1.4.1.3224.16.1.4.0',
      nsResCpuLast1Min => '1.3.6.1.4.1.3224.16.1.2.0',
      nsResCpuLast5Min => '1.3.6.1.4.1.3224.16.1.3.0',
      nsResMemAllocate => '1.3.6.1.4.1.3224.16.2.1.0',
      nsResMemFrag => '1.3.6.1.4.1.3224.16.2.3.0',
      nsResMemLeft => '1.3.6.1.4.1.3224.16.2.2.0',
      nsResSessAllocate => '1.3.6.1.4.1.3224.16.3.2.0',
      nsResSessFailed => '1.3.6.1.4.1.3224.16.3.4.0',
      nsResSessMaxium => '1.3.6.1.4.1.3224.16.3.3.0',
  },
  'NETSCREEN-CHASSIS-MIB' => {
      nsPowerTable => '1.3.6.1.4.1.3224.21.1',
      nsPowerEntry => '1.3.6.1.4.1.3224.21.1.1',
      nsPowerId => '1.3.6.1.4.1.3224.21.1.1.1',
      nsPowerStatus => '1.3.6.1.4.1.3224.21.1.1.2',
      nsPowerStatusDefinition => {
          0 => 'fail',
          1 => 'good',
      },
      nsPowerDesc => '1.3.6.1.4.1.3224.21.1.1.3',
      nsFanTable => '1.3.6.1.4.1.3224.21.2',
      nsFanEntry => '1.3.6.1.4.1.3224.21.2.1',
      nsFanId => '1.3.6.1.4.1.3224.21.2.1.1',
      nsFanStatus => '1.3.6.1.4.1.3224.21.2.1.2',
      nsFanStatusDefinition => {
          0 => 'fail',
          1 => 'good',
          2 => 'notInstalled',
      },
      nsFanDesc => '1.3.6.1.4.1.3224.21.2.1.3',
      sysBatteryStatus => '1.3.6.1.4.1.3224.21.3.0',
      sysBatteryStatusDefinition => {
          1 => 'good',
          2 => 'error',
      },
      nsTemperatureTable => '1.3.6.1.4.1.3224.21.4',
      nsTemperatureEntry => '1.3.6.1.4.1.3224.21.4.1',
      nsTemperatureId => '1.3.6.1.4.1.3224.21.4.1.1',
      nsTemperatureSlotId => '1.3.6.1.4.1.3224.21.4.1.2',
      nsTemperatureCur => '1.3.6.1.4.1.3224.21.4.1.3',
      nsTemperatureDesc => '1.3.6.1.4.1.3224.21.4.1.4',
      nsSlotTable => '1.3.6.1.4.1.3224.21.5',
      nsSlotEntry => '1.3.6.1.4.1.3224.21.5.1',
      nsSlotId => '1.3.6.1.4.1.3224.21.5.1.1',
      nsSlotType => '1.3.6.1.4.1.3224.21.5.1.2',
      nsSlotStatus => '1.3.6.1.4.1.3224.21.5.1.3',
      nsSlotStatusDefinition => {
          0 => 'fail',
          1 => 'good',
          2 => 'notInstalled',
      },
      nsSlotSN => '1.3.6.1.4.1.3224.21.5.1.4',
  },
  'ATTACK-MIB' => { # Blue Coat
      deviceAttackTable => '1.3.6.1.4.1.3417.2.3.1.1.1',
      deviceAttackEntry => '1.3.6.1.4.1.3417.2.3.1.1.1.1',
      deviceAttackIndex => '1.3.6.1.4.1.3417.2.3.1.1.1.1.1',
      deviceAttackName => '1.3.6.1.4.1.3417.2.3.1.1.1.1.2',
      deviceAttackStatus => '1.3.6.1.4.1.3417.2.3.1.1.1.1.3',
      deviceAttackStatusDefinition => {
          1 => 'no-attack',
          2 => 'under-attack',
      },
      deviceAttackTime => '1.3.6.1.4.1.3417.2.3.1.1.1.1.4',
  },
  'DISK-MIB' => {
      deviceDiskValueTable => '1.3.6.1.4.1.3417.2.2.1.1.1',
      deviceDiskValueEntry => '1.3.6.1.4.1.3417.2.2.1.1.1.1',
      deviceDiskIndex => '1.3.6.1.4.1.3417.2.2.1.1.1.1.1',
      deviceDiskTrapEnabled => '1.3.6.1.4.1.3417.2.2.1.1.1.1.2',
      deviceDiskStatus => '1.3.6.1.4.1.3417.2.2.1.1.1.1.3',
      deviceDiskStatusDefinition => {
      1 => 'present',
      2 => 'initializing',
      3 => 'inserted',
      4 => 'offline',
      5 => 'removed',
      6 => 'not-present',
      7 => 'empty',
      8 => 'bad',
      9 => 'unknown',
      },
      deviceDiskTimeStamp => '1.3.6.1.4.1.3417.2.2.1.1.1.1.4',
      deviceDiskVendor => '1.3.6.1.4.1.3417.2.2.1.1.1.1.5',
      deviceDiskProduct => '1.3.6.1.4.1.3417.2.2.1.1.1.1.6',
      deviceDiskRevision => '1.3.6.1.4.1.3417.2.2.1.1.1.1.7',
      deviceDiskSerialN => '1.3.6.1.4.1.3417.2.2.1.1.1.1.8',
      deviceDiskBlockSize => '1.3.6.1.4.1.3417.2.2.1.1.1.1.9',
      deviceDiskBlockCount => '1.3.6.1.4.1.3417.2.2.1.1.1.1.10',
  },
  'SENSOR-MIB' => {
      deviceSensorValueTable => '1.3.6.1.4.1.3417.2.1.1.1.1',
      deviceSensorValueEntry => '1.3.6.1.4.1.3417.2.1.1.1.1.1',
      deviceSensorIndex => '1.3.6.1.4.1.3417.2.1.1.1.1.1.1',
      deviceSensorTrapEnabled => '1.3.6.1.4.1.3417.2.1.1.1.1.1.2',
      deviceSensorUnits => '1.3.6.1.4.1.3417.2.1.1.1.1.1.3',
      deviceSensorUnitsDefinition => {
      1 => 'other',
      2 => 'truthvalue',
      3 => 'specialEnum',
      4 => 'volts',
      5 => 'celsius',
      6 => 'rpm',
      },
      deviceSensorScale => '1.3.6.1.4.1.3417.2.1.1.1.1.1.4',
      deviceSensorValue => '1.3.6.1.4.1.3417.2.1.1.1.1.1.5',
      deviceSensorCode => '1.3.6.1.4.1.3417.2.1.1.1.1.1.6',
      deviceSensorCodeDefinition => {
      1 => 'ok',
      2 => 'unknown',
      3 => 'not-installed',
      4 => 'voltage-low-warning',
      5 => 'voltage-low-critical',
      6 => 'no-power',
      7 => 'voltage-high-warning',
      8 => 'voltage-high-critical',
      9 => 'voltage-high-severe',
      10 => 'temperature-high-warning',
      11 => 'temperature-high-critical',
      12 => 'temperature-high-severe',
      13 => 'fan-slow-warning',
      14 => 'fan-slow-critical',
      15 => 'fan-stopped',
      },
      deviceSensorStatus => '1.3.6.1.4.1.3417.2.1.1.1.1.1.7',
      deviceSensorStatusDefinition => {
      1 => 'ok',
      2 => 'unavailable',
      3 => 'nonoperational',
      },
      deviceSensorTimeStamp => '1.3.6.1.4.1.3417.2.1.1.1.1.1.8',
      deviceSensorName => '1.3.6.1.4.1.3417.2.1.1.1.1.1.9',
  },
  'SYSTEM-RESOURCES-MIB' => {
      cpuIndex => '1.3.6.1.4.1.3417.2.8.1.1.0',
      cpuName => '1.3.6.1.4.1.3417.2.8.1.2.0',
      cpuUtilizationValue => '1.3.6.1.4.1.3417.2.8.1.3.0',
      cpuWarningThreshold => '1.3.6.1.4.1.3417.2.8.1.4.0',
      cpuWarningInterval => '1.3.6.1.4.1.3417.2.8.1.5.0',
      cpuCriticalThreshold => '1.3.6.1.4.1.3417.2.8.1.6.0',
      cpuCriticalInterval => '1.3.6.1.4.1.3417.2.8.1.7.0',
      cpuNotificationType => '1.3.6.1.4.1.3417.2.8.1.8.0',
      cpuCurrentState => '1.3.6.1.4.1.3417.2.8.1.9.0',
      cpuPreviousState => '1.3.6.1.4.1.3417.2.8.1.10.0',
      cpuLastChangeTime => '1.3.6.1.4.1.3417.2.8.1.11.0',
      cpuEvent => '1.3.6.1.4.1.3417.2.8.1.12',
      cpuTrap => '1.3.6.1.4.1.3417.2.8.1.12.1',
      memory => '1.3.6.1.4.1.3417.2.8.2',
      memIndex => '1.3.6.1.4.1.3417.2.8.2.1.0',
      memName => '1.3.6.1.4.1.3417.2.8.2.2.0',
      memPressureValue => '1.3.6.1.4.1.3417.2.8.2.3.0',
      memWarningThreshold => '1.3.6.1.4.1.3417.2.8.2.4.0',
      memWarningInterval => '1.3.6.1.4.1.3417.2.8.2.5.0',
      memCriticalThreshold => '1.3.6.1.4.1.3417.2.8.2.6.0',
      memCriticalInterval => '1.3.6.1.4.1.3417.2.8.2.7.0',
      memNotificationType => '1.3.6.1.4.1.3417.2.8.2.8.0',
      memCurrentState => '1.3.6.1.4.1.3417.2.8.2.9.0',
      memPreviousState => '1.3.6.1.4.1.3417.2.8.2.10.0',
      memLastChangeTime => '1.3.6.1.4.1.3417.2.8.2.11.0',
      memEvent => '1.3.6.1.4.1.3417.2.8.2.12',
      memTrap => '1.3.6.1.4.1.3417.2.8.2.12.1',
      network => '1.3.6.1.4.1.3417.2.8.3',
      netTable => '1.3.6.1.4.1.3417.2.8.3.1',
      netEntry => '1.3.6.1.4.1.3417.2.8.3.1.1',
      netIndex => '1.3.6.1.4.1.3417.2.8.3.1.1.1',
      netName => '1.3.6.1.4.1.3417.2.8.3.1.1.2',
      netUtilizationValue => '1.3.6.1.4.1.3417.2.8.3.1.1.3',
      netWarningThreshold => '1.3.6.1.4.1.3417.2.8.3.1.1.4',
      netWarningInterval => '1.3.6.1.4.1.3417.2.8.3.1.1.5',
      netCriticalThreshold => '1.3.6.1.4.1.3417.2.8.3.1.1.6',
      netCriticalInterval => '1.3.6.1.4.1.3417.2.8.3.1.1.7',
      netNotificationType => '1.3.6.1.4.1.3417.2.8.3.1.1.8',
      netCurrentState => '1.3.6.1.4.1.3417.2.8.3.1.1.9',
      netPreviousState => '1.3.6.1.4.1.3417.2.8.3.1.1.10',
      netLastChangeTime => '1.3.6.1.4.1.3417.2.8.3.1.1.11',
  },
  'USAGE-MIB' => {
      deviceUsageTable => '1.3.6.1.4.1.3417.2.4.1.1',
      deviceUsageEntry => '1.3.6.1.4.1.3417.2.4.1.1.1',
      deviceUsageIndex => '1.3.6.1.4.1.3417.2.4.1.1.1.1',
      deviceUsageTrapEnabled => '1.3.6.1.4.1.3417.2.4.1.1.1.2',
      deviceUsageName => '1.3.6.1.4.1.3417.2.4.1.1.1.3',
      deviceUsagePercent => '1.3.6.1.4.1.3417.2.4.1.1.1.4',
      deviceUsageHigh => '1.3.6.1.4.1.3417.2.4.1.1.1.5',
      deviceUsageStatus => '1.3.6.1.4.1.3417.2.4.1.1.1.6',
      deviceUsageStatusDefinition => {
          1 => 'ok',
          2 => 'high',
      },
      deviceUsageTime => '1.3.6.1.4.1.3417.2.4.1.1.1.7',
  },
  'ENTITY-SENSOR-MIB' => {
      entitySensorObjects => '1.3.6.1.2.1.99.1',
      entitySensorConformance => '1.3.6.1.2.1.99.3',
      entitySensorObjects => '1.3.6.1.2.1.99.1',
      entPhySensorTable => '1.3.6.1.2.1.99.1.1',
      entPhySensorEntry => '1.3.6.1.2.1.99.1.1.1',
      entPhySensorType => '1.3.6.1.2.1.99.1.1.1.1',
      entPhySensorTypeDefinition => {
        1 => 'other',
        2 => 'unknown',
        3 => 'voltsAC',
        4 => 'voltsDC',
        5 => 'amperes',
        6 => 'watts',
        7 => 'hertz',
        8 => 'celsius',
        9 => 'percentRH',
        10 => 'rpm',
        11 => 'cmm',
        12 => 'truthvalue',
      },
      entPhySensorScale => '1.3.6.1.2.1.99.1.1.1.2',
      entPhySensorScaleDefinition => {
        1 => 'yocto',
        2 => 'zepto',
        3 => 'atto',
        4 => 'femto',
        5 => 'pico',
        6 => 'nano',
        7 => 'micro',
        8 => 'milli',
        9 => 'units',
        10 => 'kilo',
        11 => 'mega',
        12 => 'giga',
        13 => 'tera',
        14 => 'exa',
        15 => 'peta',
        16 => 'zetta',
        17 => 'yotta',
      },
      entPhySensorPrecision => '1.3.6.1.2.1.99.1.1.1.3',
      entPhySensorValue => '1.3.6.1.2.1.99.1.1.1.4',
      entPhySensorOperStatus => '1.3.6.1.2.1.99.1.1.1.5',
      entPhySensorOperStatusDefinition => {
        1 => 'ok',
        2 => 'unavailable',
        3 => 'nonoperational',
      },
      entPhySensorUnitsDisplay => '1.3.6.1.2.1.99.1.1.1.6',
      entPhySensorValueTimeStamp => '1.3.6.1.2.1.99.1.1.1.7',
      entPhySensorValueUpdateRate => '1.3.6.1.2.1.99.1.1.1.8',
      entitySensorCompliances => '1.3.6.1.2.1.99.3.1',
      entitySensorGroups => '1.3.6.1.2.1.99.3.2',
  },
  'BLUECOAT-SG-PROXY-MIB' => {
      blueCoatMgmt => '1.3.6.1.4.1.3417.2',
      bluecoatSGProxyMIB => '1.3.6.1.4.1.3417.2.11',
      sgProxyConfig => '1.3.6.1.4.1.3417.2.11.1',
      sgProxySystem => '1.3.6.1.4.1.3417.2.11.2',
      sgProxyMemAvailable => '1.3.6.1.4.1.3417.2.11.2.3.1.0',
      sgProxyMemCacheUsage => '1.3.6.1.4.1.3417.2.11.2.3.2.0',
      sgProxyMemSysUsage => '1.3.6.1.4.1.3417.2.11.2.3.3.0',
      sgProxyMemPressure => '1.3.6.1.4.1.3417.2.11.2.3.4.0',
      sgProxyCpuCoreTable => '1.3.6.1.4.1.3417.2.11.2.4',
      sgProxyCpuCoreEntry => '1.3.6.1.4.1.3417.2.11.2.4.1',
      sgProxyCpuCoreIndex => '1.3.6.1.4.1.3417.2.11.2.4.1.1',
      sgProxyCpuCoreUpTime => '1.3.6.1.4.1.3417.2.11.2.4.1.2',
      sgProxyCpuCoreBusyTime => '1.3.6.1.4.1.3417.2.11.2.4.1.3',
      sgProxyCpuCoreIdleTime => '1.3.6.1.4.1.3417.2.11.2.4.1.4',
      sgProxyCpuCoreUpTimeSinceLastAccess => '1.3.6.1.4.1.3417.2.11.2.4.1.5',
      sgProxyCpuCoreBusyTimeSinceLastAccess => '1.3.6.1.4.1.3417.2.11.2.4.1.6',
      sgProxyCpuCoreIdleTimeSinceLastAccess => '1.3.6.1.4.1.3417.2.11.2.4.1.7',
      sgProxyCpuCoreBusyPerCent => '1.3.6.1.4.1.3417.2.11.2.4.1.8',
      sgProxyCpuCoreIdlePerCent => '1.3.6.1.4.1.3417.2.11.2.4.1.9',
      sgProxyHttp => '1.3.6.1.4.1.3417.2.11.3',
      sgProxyHttpPerf => '1.3.6.1.4.1.3417.2.11.3.1',
      sgProxyHttpClient => '1.3.6.1.4.1.3417.2.11.3.1.1',
      sgProxyHttpServer => '1.3.6.1.4.1.3417.2.11.3.1.2',
      sgProxyHttpConnections => '1.3.6.1.4.1.3417.2.11.3.1.3',
      sgProxyHttpClientConnections => '1.3.6.1.4.1.3417.2.11.3.1.3.1',
      sgProxyHttpClientConnectionsActive => '1.3.6.1.4.1.3417.2.11.3.1.3.2',
      sgProxyHttpClientConnectionsIdle => '1.3.6.1.4.1.3417.2.11.3.1.3.3',
      sgProxyHttpServerConnections => '1.3.6.1.4.1.3417.2.11.3.1.3.4',
      sgProxyHttpServerConnectionsActive => '1.3.6.1.4.1.3417.2.11.3.1.3.5',
      sgProxyHttpServerConnectionsIdle => '1.3.6.1.4.1.3417.2.11.3.1.3.6',
      sgProxyHttpResponse => '1.3.6.1.4.1.3417.2.11.3.2',
      sgProxyHttpResponseTime => '1.3.6.1.4.1.3417.2.11.3.2.1',
      sgProxyHttpResponseTimeAll => '1.3.6.1.4.1.3417.2.11.3.2.1.1', #ok
      sgProxyHttpResponseFirstByte => '1.3.6.1.4.1.3417.2.11.3.2.1.2',
      sgProxyHttpResponseByteRate => '1.3.6.1.4.1.3417.2.11.3.2.1.3',
      sgProxyHttpResponseSize => '1.3.6.1.4.1.3417.2.11.3.2.1.4',
  },
  'PROXY-MIB' => {
      proxyMemUsage => '1.3.6.1.3.25.17.1.1.0',
      proxyStorage => '1.3.6.1.3.25.17.1.2.0',
      proxyCpuUsage => '1.3.6.1.3.25.17.1.3.0',
      proxyUpTime => '1.3.6.1.3.25.17.1.4.0',
      proxyConfig => '1.3.6.1.3.25.17.2',
      proxyAdmin => '1.3.6.1.3.25.17.2.1.0',
      proxySoftware => '1.3.6.1.3.25.17.2.2.0',
      proxyVersion => '1.3.6.1.3.25.17.2.3.0',
      proxySysPerf => '1.3.6.1.3.25.17.3.1',
      proxyProtoPerf => '1.3.6.1.3.25.17.3.2',
      proxySysPerf => '1.3.6.1.3.25.17.3.1',
      proxyCpuLoad => '1.3.6.1.3.25.17.3.1.1.0',
      proxyNumObjects => '1.3.6.1.3.25.17.3.1.2.0',
  },
  'RESOURCE-MIB' => {
      cpuIndex => '1.3.6.1.4.1.3417.2.8.1.1.0',
      cpuName => '1.3.6.1.4.1.3417.2.8.1.2.0',
      cpuUtilizationValue => '1.3.6.1.4.1.3417.2.8.1.3.0',
      cpuWarningThreshold => '1.3.6.1.4.1.3417.2.8.1.4.0',
      cpuWarningInterval => '1.3.6.1.4.1.3417.2.8.1.5.0',
      cpuCriticalThreshold => '1.3.6.1.4.1.3417.2.8.1.6.0',
      cpuCriticalInterval => '1.3.6.1.4.1.3417.2.8.1.7.0',
      cpuNotificationType => '1.3.6.1.4.1.3417.2.8.1.8.0',
      cpuCurrentState => '1.3.6.1.4.1.3417.2.8.1.9.0',
      cpuPreviousState => '1.3.6.1.4.1.3417.2.8.1.10.0',
      cpuLastChangeTime => '1.3.6.1.4.1.3417.2.8.1.11.0',
      cpuEvent => '1.3.6.1.4.1.3417.2.8.1.12',
      cpuTrap => '1.3.6.1.4.1.3417.2.8.1.12.1',
      memory => '1.3.6.1.4.1.3417.2.8.2',
      memIndex => '1.3.6.1.4.1.3417.2.8.2.1.0',
      memName => '1.3.6.1.4.1.3417.2.8.2.2.0',
      memPressureValue => '1.3.6.1.4.1.3417.2.8.2.3.0',
      memWarningThreshold => '1.3.6.1.4.1.3417.2.8.2.4.0',
      memWarningInterval => '1.3.6.1.4.1.3417.2.8.2.5.0',
      memCriticalThreshold => '1.3.6.1.4.1.3417.2.8.2.6.0',
      memCriticalInterval => '1.3.6.1.4.1.3417.2.8.2.7.0',
      memNotificationType => '1.3.6.1.4.1.3417.2.8.2.8.0',
      memCurrentState => '1.3.6.1.4.1.3417.2.8.2.9.0',
      memPreviousState => '1.3.6.1.4.1.3417.2.8.2.10.0',
      memLastChangeTime => '1.3.6.1.4.1.3417.2.8.2.11.0',
      memEvent => '1.3.6.1.4.1.3417.2.8.2.12',
      memTrap => '1.3.6.1.4.1.3417.2.8.2.12.1',
      network => '1.3.6.1.4.1.3417.2.8.3',
      netTable => '1.3.6.1.4.1.3417.2.8.3.1',
      netEntry => '1.3.6.1.4.1.3417.2.8.3.1.1',
      netIndex => '1.3.6.1.4.1.3417.2.8.3.1.1.1',
      netName => '1.3.6.1.4.1.3417.2.8.3.1.1.2',
      netUtilizationValue => '1.3.6.1.4.1.3417.2.8.3.1.1.3',
      netWarningThreshold => '1.3.6.1.4.1.3417.2.8.3.1.1.4',
      netWarningInterval => '1.3.6.1.4.1.3417.2.8.3.1.1.5',
      netCriticalThreshold => '1.3.6.1.4.1.3417.2.8.3.1.1.6',
      netCriticalInterval => '1.3.6.1.4.1.3417.2.8.3.1.1.7',
      netNotificationType => '1.3.6.1.4.1.3417.2.8.3.1.1.8',
      netCurrentState => '1.3.6.1.4.1.3417.2.8.3.1.1.9',
      netPreviousState => '1.3.6.1.4.1.3417.2.8.3.1.1.10',
      netLastChangeTime => '1.3.6.1.4.1.3417.2.8.3.1.1.11',
  },
  'BLUECOAT-AV-MIB' => {
      avEngineVersion => '1.3.6.1.4.1.3417.2.10.1.5.0',
      avErrorCode => '1.3.6.1.4.1.3417.2.10.2.5.0',
      avErrorDetails => '1.3.6.1.4.1.3417.2.10.2.6.0',
      avFilesScanned => '1.3.6.1.4.1.3417.2.10.1.1.0',
      avICTMWarningReason => '1.3.6.1.4.1.3417.2.10.2.8.0',
      avInstalledFirmwareVersion => '1.3.6.1.4.1.3417.2.10.1.9.0',
      avLicenseDaysRemaining => '1.3.6.1.4.1.3417.2.10.1.7.0',
      avPatternDateTime => '1.3.6.1.4.1.3417.2.10.1.4.0',
      avPatternVersion => '1.3.6.1.4.1.3417.2.10.1.3.0',
      avPreviousFirmwareVersion => '1.3.6.1.4.1.3417.2.10.2.7.0',
      avPublishedFirmwareVersion => '1.3.6.1.4.1.3417.2.10.1.8.0',
      avSlowICAPConnections => '1.3.6.1.4.1.3417.2.10.1.10.0',
      avUpdateFailureReason => '1.3.6.1.4.1.3417.2.10.2.1.0',
      avUrl => '1.3.6.1.4.1.3417.2.10.2.2.0',
      avVendorName => '1.3.6.1.4.1.3417.2.10.1.6.0',
      avVirusDetails => '1.3.6.1.4.1.3417.2.10.2.4.0',
      avVirusesDetected => '1.3.6.1.4.1.3417.2.10.1.2.0',
      avVirusName => '1.3.6.1.4.1.3417.2.10.2.3.0',
  },
  'FOUNDRY-SN-AGENT-MIB' => {
      snAgGblCpuUtil1SecAvg => '1.3.6.1.4.1.1991.1.1.2.1.50.0',
      snAgGblCpuUtil5SecAvg => '1.3.6.1.4.1.1991.1.1.2.1.51.0',
      snAgGblCpuUtil1MinAvg => '1.3.6.1.4.1.1991.1.1.2.1.52.0',
      snAgGblDynMemUtil => '1.3.6.1.4.1.1991.1.1.2.1.53.0',
      snAgGblDynMemTotal => '1.3.6.1.4.1.1991.1.1.2.1.54.0',
      snAgGblDynMemFree => '1.3.6.1.4.1.1991.1.1.2.1.55.0',

      snAgentCpuUtilTable => '1.3.6.1.4.1.1991.1.1.2.11.1',
      snAgentCpuUtilEntry => '1.3.6.1.4.1.1991.1.1.2.11.1.1',
      snAgentCpuUtilSlotNum => '1.3.6.1.4.1.1991.1.1.2.11.1.1.1',
      snAgentCpuUtilCpuId => '1.3.6.1.4.1.1991.1.1.2.11.1.1.2',
      snAgentCpuUtilInterval => '1.3.6.1.4.1.1991.1.1.2.11.1.1.3',
      snAgentCpuUtilValue => '1.3.6.1.4.1.1991.1.1.2.11.1.1.4',
      snAgentCpuUtilPercent => '1.3.6.1.4.1.1991.1.1.2.11.1.1.5',
      snAgentCpuUtil100thPercent => '1.3.6.1.4.1.1991.1.1.2.11.1.1.6',

      snChasPwrSupplyTable => '1.3.6.1.4.1.1991.1.1.1.2.1',
      snChasPwrSupplyEntry => '1.3.6.1.4.1.1991.1.1.1.2.1.1',
      snChasPwrSupplyIndex => '1.3.6.1.4.1.1991.1.1.1.2.1.1.1',
      snChasPwrSupplyDescription => '1.3.6.1.4.1.1991.1.1.1.2.1.1.2',
      snChasPwrSupplyOperStatus => '1.3.6.1.4.1.1991.1.1.1.2.1.1.3',
      snChasPwrSupplyOperStatusDefinition => {
          1 => 'other',
          2 => 'normal',
          3 => 'failure',
      },
      snChasFan => '1.3.6.1.4.1.1991.1.1.1.3',
      snChasFanTable => '1.3.6.1.4.1.1991.1.1.1.3.1',
      snChasFanEntry => '1.3.6.1.4.1.1991.1.1.1.3.1.1',
      snChasFanIndex => '1.3.6.1.4.1.1991.1.1.1.3.1.1.1',
      snChasFanDescription => '1.3.6.1.4.1.1991.1.1.1.3.1.1.2',
      snChasFanOperStatus => '1.3.6.1.4.1.1991.1.1.1.3.1.1.3',
      snChasFanOperStatusDefinition => {
          1 => 'other',
          2 => 'normal',
          3 => 'failure',
      },
      snAgentTempTable => '1.3.6.1.4.1.1991.1.1.2.13.1',
      snAgentTempEntry => '1.3.6.1.4.1.1991.1.1.2.13.1.1',
      snAgentTempSlotNum => '1.3.6.1.4.1.1991.1.1.2.13.1.1.1',
      # sensor 1 - intake temperature, sensor 2 - exhaust-side temperature
      snAgentTempSensorId => '1.3.6.1.4.1.1991.1.1.2.13.1.1.2',
      snAgentTempSensorDescr => '1.3.6.1.4.1.1991.1.1.2.13.1.1.3',
      # This value is displayed in units of 0.5 Celsius. Valid: 110 - 250
      snAgentTempValue => '1.3.6.1.4.1.1991.1.1.2.13.1.1.4',
  },
  'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB' => {
      snL4Gen => '1.3.6.1.4.1.1991.1.1.4.1',
      snL4MaxSessionLimit => '1.3.6.1.4.1.1991.1.1.4.1.1.0',
      snL4TcpSynLimit => '1.3.6.1.4.1.1991.1.1.4.1.2.0',
      snL4slbGlobalSDAType => '1.3.6.1.4.1.1991.1.1.4.1.3.0',
      snL4slbTotalConnections => '1.3.6.1.4.1.1991.1.1.4.1.4.0',
      snL4slbLimitExceeds => '1.3.6.1.4.1.1991.1.1.4.1.5.0',
      snL4slbForwardTraffic => '1.3.6.1.4.1.1991.1.1.4.1.6.0',
      snL4slbReverseTraffic => '1.3.6.1.4.1.1991.1.1.4.1.7.0',
      snL4slbDrops => '1.3.6.1.4.1.1991.1.1.4.1.8.0',
      snL4slbDangling => '1.3.6.1.4.1.1991.1.1.4.1.9.0',
      snL4slbDisableCount => '1.3.6.1.4.1.1991.1.1.4.1.10.0',
      snL4slbAged => '1.3.6.1.4.1.1991.1.1.4.1.11.0',
      snL4slbFinished => '1.3.6.1.4.1.1991.1.1.4.1.12.0',
      snL4FreeSessionCount => '1.3.6.1.4.1.1991.1.1.4.1.13.0',
      snL4BackupInterface => '1.3.6.1.4.1.1991.1.1.4.1.14.0',
      snL4BackupMacAddr => '1.3.6.1.4.1.1991.1.1.4.1.15.0',
      snL4Active => '1.3.6.1.4.1.1991.1.1.4.1.16.0',
      snL4Redundancy => '1.3.6.1.4.1.1991.1.1.4.1.17.0',
      snL4Backup => '1.3.6.1.4.1.1991.1.1.4.1.18.0',
      snL4BecomeActive => '1.3.6.1.4.1.1991.1.1.4.1.19.0',
      snL4BecomeStandBy => '1.3.6.1.4.1.1991.1.1.4.1.20.0',
      snL4BackupState => '1.3.6.1.4.1.1991.1.1.4.1.21.0',
      snL4NoPDUSent => '1.3.6.1.4.1.1991.1.1.4.1.22.0',
      snL4NoPDUCount => '1.3.6.1.4.1.1991.1.1.4.1.23.0',
      snL4NoPortMap => '1.3.6.1.4.1.1991.1.1.4.1.24.0',
      snL4unsuccessfulConn => '1.3.6.1.4.1.1991.1.1.4.1.25.0',
      snL4PingInterval => '1.3.6.1.4.1.1991.1.1.4.1.26.0',
      snL4PingRetry => '1.3.6.1.4.1.1991.1.1.4.1.27.0',
      snL4TcpAge => '1.3.6.1.4.1.1991.1.1.4.1.28.0',
      snL4UdpAge => '1.3.6.1.4.1.1991.1.1.4.1.29.0',
      snL4EnableMaxSessionLimitReachedTrap => '1.3.6.1.4.1.1991.1.1.4.1.30.0',
      snL4EnableTcpSynLimitReachedTrap => '1.3.6.1.4.1.1991.1.1.4.1.31.0',
      snL4EnableRealServerUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.32.0',
      snL4EnableRealServerDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.33.0',
      snL4EnableRealServerPortUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.34.0',
      snL4EnableRealServerPortDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.35.0',
      snL4EnableRealServerMaxConnLimitReachedTrap => '1.3.6.1.4.1.1991.1.1.4.1.36.0',
      snL4EnableBecomeStandbyTrap => '1.3.6.1.4.1.1991.1.1.4.1.37.0',
      snL4EnableBecomeActiveTrap => '1.3.6.1.4.1.1991.1.1.4.1.38.0',
      snL4slbRouterInterfacePortMask => '1.3.6.1.4.1.1991.1.1.4.1.39.0',
      snL4MaxNumWebCacheGroup => '1.3.6.1.4.1.1991.1.1.4.1.40.0',
      snL4MaxNumWebCachePerGroup => '1.3.6.1.4.1.1991.1.1.4.1.41.0',
      snL4WebCacheStateful => '1.3.6.1.4.1.1991.1.1.4.1.42.0',
      snL4EnableGslbHealthCheckIpUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.43.0',
      snL4EnableGslbHealthCheckIpDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.44.0',
      snL4EnableGslbHealthCheckIpPortUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.45.0',
      snL4EnableGslbHealthCheckIpPortDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.46.0',
      snL4EnableGslbRemoteGslbSiDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.47.0',
      snL4EnableGslbRemoteGslbSiUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.48.0',
      snL4EnableGslbRemoteSiDownTrap => '1.3.6.1.4.1.1991.1.1.4.1.49.0',
      snL4EnableGslbRemoteSiUpTrap => '1.3.6.1.4.1.1991.1.1.4.1.50.0',
      snL4slbRouterInterfacePortList => '1.3.6.1.4.1.1991.1.1.4.1.51.0',
      snL4VirtualServer => '1.3.6.1.4.1.1991.1.1.4.2',
      snL4VirtualServerTable => '1.3.6.1.4.1.1991.1.1.4.2.1',
      snL4VirtualServerEntry => '1.3.6.1.4.1.1991.1.1.4.2.1.1',
      snL4VirtualServerIndex => '1.3.6.1.4.1.1991.1.1.4.2.1.1.1',
      snL4VirtualServerName => '1.3.6.1.4.1.1991.1.1.4.2.1.1.2',
      snL4VirtualServerVirtualIP => '1.3.6.1.4.1.1991.1.1.4.2.1.1.3',
      snL4VirtualServerAdminStatus => '1.3.6.1.4.1.1991.1.1.4.2.1.1.4',
      snL4VirtualServerAdminStatusDefinition => 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB::L4Status',
      snL4VirtualServerSDAType => '1.3.6.1.4.1.1991.1.1.4.2.1.1.5',
      snL4VirtualServerSDATypeDefinition => {
          0 => 'default',
          1 => 'leastconnection',
          2 => 'roundrobin',
          3 => 'weighted',
      },
      snL4VirtualServerRowStatus => '1.3.6.1.4.1.1991.1.1.4.2.1.1.6',
      snL4VirtualServerDeleteState => '1.3.6.1.4.1.1991.1.1.4.2.1.1.7',
      snL4VirtualServerDeleteStateDefinition => 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB::L4DeleteState',
      snL4RealServer => '1.3.6.1.4.1.1991.1.1.4.3',
      snL4RealServerTable => '1.3.6.1.4.1.1991.1.1.4.3.1',
      snL4RealServerEntry => '1.3.6.1.4.1.1991.1.1.4.3.1.1',
      snL4RealServerIndex => '1.3.6.1.4.1.1991.1.1.4.3.1.1.1',
      snL4RealServerName => '1.3.6.1.4.1.1991.1.1.4.3.1.1.2',
      snL4RealServerIP => '1.3.6.1.4.1.1991.1.1.4.3.1.1.3',
      snL4RealServerAdminStatus => '1.3.6.1.4.1.1991.1.1.4.3.1.1.4',
      snL4RealServerAdminStatusDefinition => 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB::L4Status',
      snL4RealServerMaxConnections => '1.3.6.1.4.1.1991.1.1.4.3.1.1.5',
      snL4RealServerWeight => '1.3.6.1.4.1.1991.1.1.4.3.1.1.6',
      snL4RealServerRowStatus => '1.3.6.1.4.1.1991.1.1.4.3.1.1.7',
      snL4RealServerDeleteState => '1.3.6.1.4.1.1991.1.1.4.3.1.1.8',
      snL4VirtualServerPort => '1.3.6.1.4.1.1991.1.1.4.4',
      snL4VirtualServerPortTable => '1.3.6.1.4.1.1991.1.1.4.4.1',
      snL4VirtualServerPortEntry => '1.3.6.1.4.1.1991.1.1.4.4.1.1',
      snL4VirtualServerPortIndex => '1.3.6.1.4.1.1991.1.1.4.4.1.1.1',
      snL4VirtualServerPortServerName => '1.3.6.1.4.1.1991.1.1.4.4.1.1.2',
      snL4VirtualServerPortPort => '1.3.6.1.4.1.1991.1.1.4.4.1.1.3',
      snL4VirtualServerPortAdminStatus => '1.3.6.1.4.1.1991.1.1.4.4.1.1.4',
      snL4VirtualServerPortAdminStatusDefinition => 'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB::L4Status',
      snL4VirtualServerPortSticky => '1.3.6.1.4.1.1991.1.1.4.4.1.1.5',
      snL4VirtualServerPortStickyDefinition => {
          0 => 'disabled',
          1 => 'enabled',
      },
      snL4VirtualServerPortConcurrent => '1.3.6.1.4.1.1991.1.1.4.4.1.1.6',
      snL4VirtualServerPortConcurrentDefinition => {
          0 => 'disabled',
          1 => 'enabled',
      },
      snL4VirtualServerPortRowStatus => '1.3.6.1.4.1.1991.1.1.4.4.1.1.7',
      snL4VirtualServerPortDeleteState => '1.3.6.1.4.1.1991.1.1.4.4.1.1.8',
      snL4RealServerPort => '1.3.6.1.4.1.1991.1.1.4.5',
      snL4RealServerPortTable => '1.3.6.1.4.1.1991.1.1.4.5.1',
      snL4RealServerPortEntry => '1.3.6.1.4.1.1991.1.1.4.5.1.1',
      snL4RealServerPortIndex => '1.3.6.1.4.1.1991.1.1.4.5.1.1.1',
      snL4RealServerPortServerName => '1.3.6.1.4.1.1991.1.1.4.5.1.1.2',
      snL4RealServerPortPort => '1.3.6.1.4.1.1991.1.1.4.5.1.1.3',
      snL4RealServerPortAdminStatus => '1.3.6.1.4.1.1991.1.1.4.5.1.1.4',
      snL4RealServerPortRowStatus => '1.3.6.1.4.1.1991.1.1.4.5.1.1.5',
      snL4RealServerPortDeleteState => '1.3.6.1.4.1.1991.1.1.4.5.1.1.6',
      snL4Bind => '1.3.6.1.4.1.1991.1.1.4.6',
      snL4BindTable => '1.3.6.1.4.1.1991.1.1.4.6.1',
      snL4BindEntry => '1.3.6.1.4.1.1991.1.1.4.6.1.1',
      snL4BindIndex => '1.3.6.1.4.1.1991.1.1.4.6.1.1.1',
      snL4BindVirtualServerName => '1.3.6.1.4.1.1991.1.1.4.6.1.1.2',
      snL4BindVirtualPortNumber => '1.3.6.1.4.1.1991.1.1.4.6.1.1.3',
      snL4BindRealServerName => '1.3.6.1.4.1.1991.1.1.4.6.1.1.4',
      snL4BindRealPortNumber => '1.3.6.1.4.1.1991.1.1.4.6.1.1.5',
      snL4BindRowStatus => '1.3.6.1.4.1.1991.1.1.4.6.1.1.6',
      snL4VirtualServerStatus => '1.3.6.1.4.1.1991.1.1.4.7',
      snL4VirtualServerStatusTable => '1.3.6.1.4.1.1991.1.1.4.7.1',
      snL4VirtualServerStatusEntry => '1.3.6.1.4.1.1991.1.1.4.7.1.1',
      snL4VirtualServerStatusIndex => '1.3.6.1.4.1.1991.1.1.4.7.1.1.1',
      snL4VirtualServerStatusName => '1.3.6.1.4.1.1991.1.1.4.7.1.1.2',
      snL4VirtualServerStatusReceivePkts => '1.3.6.1.4.1.1991.1.1.4.7.1.1.3',
      snL4VirtualServerStatusTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.7.1.1.4',
      snL4VirtualServerStatusTotalConnections => '1.3.6.1.4.1.1991.1.1.4.7.1.1.5',
      snL4RealServerStatus => '1.3.6.1.4.1.1991.1.1.4.8',
      snL4RealServerStatusTable => '1.3.6.1.4.1.1991.1.1.4.8.1',
      snL4RealServerStatusEntry => '1.3.6.1.4.1.1991.1.1.4.8.1.1',
      snL4RealServerStatusIndex => '1.3.6.1.4.1.1991.1.1.4.8.1.1.1',
      snL4RealServerStatusName => '1.3.6.1.4.1.1991.1.1.4.8.1.1.2',
      snL4RealServerStatusRealIP => '1.3.6.1.4.1.1991.1.1.4.8.1.1.3',
      snL4RealServerStatusReceivePkts => '1.3.6.1.4.1.1991.1.1.4.8.1.1.4',
      snL4RealServerStatusTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.8.1.1.5',
      snL4RealServerStatusCurConnections => '1.3.6.1.4.1.1991.1.1.4.8.1.1.6',
      snL4RealServerStatusTotalConnections => '1.3.6.1.4.1.1991.1.1.4.8.1.1.7',
      snL4RealServerStatusAge => '1.3.6.1.4.1.1991.1.1.4.8.1.1.8',
      snL4RealServerStatusState => '1.3.6.1.4.1.1991.1.1.4.8.1.1.9',
      snL4RealServerStatusStateDefinition => {
          0 => 'serverdisabled',
          1 => 'serverenabled',
          2 => 'serverfailed',
          3 => 'servertesting',
          4 => 'serversuspect',
          5 => 'servershutdown',
          6 => 'serveractive',
      },
      snL4RealServerStatusReassignments => '1.3.6.1.4.1.1991.1.1.4.8.1.1.10',
      snL4RealServerStatusReassignmentLimit => '1.3.6.1.4.1.1991.1.1.4.8.1.1.11',
      snL4RealServerStatusFailedPortExists => '1.3.6.1.4.1.1991.1.1.4.8.1.1.12',
      snL4RealServerStatusFailTime => '1.3.6.1.4.1.1991.1.1.4.8.1.1.13',
      snL4RealServerStatusPeakConnections => '1.3.6.1.4.1.1991.1.1.4.8.1.1.14',
      snL4VirtualServerPortStatus => '1.3.6.1.4.1.1991.1.1.4.9',
      snL4VirtualServerPortStatusTable => '1.3.6.1.4.1.1991.1.1.4.9.1',
      snL4VirtualServerPortStatusEntry => '1.3.6.1.4.1.1991.1.1.4.9.1.1',
      snL4VirtualServerPortStatusIndex => '1.3.6.1.4.1.1991.1.1.4.9.1.1.1',
      snL4VirtualServerPortStatusPort => '1.3.6.1.4.1.1991.1.1.4.9.1.1.2',
      snL4VirtualServerPortStatusServerName => '1.3.6.1.4.1.1991.1.1.4.9.1.1.3',
      snL4VirtualServerPortStatusCurrentConnection => '1.3.6.1.4.1.1991.1.1.4.9.1.1.4',
      snL4VirtualServerPortStatusTotalConnection => '1.3.6.1.4.1.1991.1.1.4.9.1.1.5',
      snL4VirtualServerPortStatusPeakConnection => '1.3.6.1.4.1.1991.1.1.4.9.1.1.6',
      snL4RealServerPortStatus => '1.3.6.1.4.1.1991.1.1.4.10',
      snL4RealServerPortStatusTable => '1.3.6.1.4.1.1991.1.1.4.10.1',
      snL4RealServerPortStatusEntry => '1.3.6.1.4.1.1991.1.1.4.10.1.1',
      snL4RealServerPortStatusIndex => '1.3.6.1.4.1.1991.1.1.4.10.1.1.1',
      snL4RealServerPortStatusPort => '1.3.6.1.4.1.1991.1.1.4.10.1.1.2',
      snL4RealServerPortStatusServerName => '1.3.6.1.4.1.1991.1.1.4.10.1.1.3',
      snL4RealServerPortStatusReassignCount => '1.3.6.1.4.1.1991.1.1.4.10.1.1.4',
      snL4RealServerPortStatusState => '1.3.6.1.4.1.1991.1.1.4.10.1.1.5',
      snL4RealServerPortStatusStateDefinition => {
          0 => 'disabled',
          1 => 'enabled',
          2 => 'failed',
          3 => 'testing',
          4 => 'suspect',
          5 => 'shutdown',
          6 => 'active',
          7 => 'unbound',
          8 => 'awaitUnbind',
          9 => 'awaitDelete',
      },
      snL4RealServerPortStatusFailTime => '1.3.6.1.4.1.1991.1.1.4.10.1.1.6',
      snL4RealServerPortStatusCurrentConnection => '1.3.6.1.4.1.1991.1.1.4.10.1.1.7',
      snL4RealServerPortStatusTotalConnection => '1.3.6.1.4.1.1991.1.1.4.10.1.1.8',
      snL4RealServerPortStatusRxPkts => '1.3.6.1.4.1.1991.1.1.4.10.1.1.9',
      snL4RealServerPortStatusTxPkts => '1.3.6.1.4.1.1991.1.1.4.10.1.1.10',
      snL4RealServerPortStatusRxBytes => '1.3.6.1.4.1.1991.1.1.4.10.1.1.11',
      snL4RealServerPortStatusTxBytes => '1.3.6.1.4.1.1991.1.1.4.10.1.1.12',
      snL4RealServerPortStatusPeakConnection => '1.3.6.1.4.1.1991.1.1.4.10.1.1.13',
      snL4Policy => '1.3.6.1.4.1.1991.1.1.4.11',
      snL4PolicyTable => '1.3.6.1.4.1.1991.1.1.4.11.1',
      snL4PolicyEntry => '1.3.6.1.4.1.1991.1.1.4.11.1.1',
      snL4PolicyId => '1.3.6.1.4.1.1991.1.1.4.11.1.1.1',
      snL4PolicyPriority => '1.3.6.1.4.1.1991.1.1.4.11.1.1.2',
      snL4PolicyScope => '1.3.6.1.4.1.1991.1.1.4.11.1.1.3',
      snL4PolicyProtocol => '1.3.6.1.4.1.1991.1.1.4.11.1.1.4',
      snL4PolicyPort => '1.3.6.1.4.1.1991.1.1.4.11.1.1.5',
      snL4PolicyRowStatus => '1.3.6.1.4.1.1991.1.1.4.11.1.1.6',
      snL4PolicyPortAccess => '1.3.6.1.4.1.1991.1.1.4.12',
      snL4PolicyPortAccessTable => '1.3.6.1.4.1.1991.1.1.4.12.1',
      snL4PolicyPortAccessEntry => '1.3.6.1.4.1.1991.1.1.4.12.1.1',
      snL4PolicyPortAccessPort => '1.3.6.1.4.1.1991.1.1.4.12.1.1.1',
      snL4PolicyPortAccessList => '1.3.6.1.4.1.1991.1.1.4.12.1.1.2',
      snL4PolicyPortAccessRowStatus => '1.3.6.1.4.1.1991.1.1.4.12.1.1.3',
      snL4Trap => '1.3.6.1.4.1.1991.1.1.4.13',
      snL4TrapRealServerIP => '1.3.6.1.4.1.1991.1.1.4.13.1.0',
      snL4TrapRealServerName => '1.3.6.1.4.1.1991.1.1.4.13.2.0',
      snL4TrapRealServerPort => '1.3.6.1.4.1.1991.1.1.4.13.3.0',
      snL4TrapRealServerCurConnections => '1.3.6.1.4.1.1991.1.1.4.13.4.0',
      snL4WebCache => '1.3.6.1.4.1.1991.1.1.4.14',
      snL4WebCacheTable => '1.3.6.1.4.1.1991.1.1.4.14.1',
      snL4WebCacheEntry => '1.3.6.1.4.1.1991.1.1.4.14.1.1',
      snL4WebCacheIP => '1.3.6.1.4.1.1991.1.1.4.14.1.1.1',
      snL4WebCacheName => '1.3.6.1.4.1.1991.1.1.4.14.1.1.2',
      snL4WebCacheAdminStatus => '1.3.6.1.4.1.1991.1.1.4.14.1.1.3',
      snL4WebCacheMaxConnections => '1.3.6.1.4.1.1991.1.1.4.14.1.1.4',
      snL4WebCacheWeight => '1.3.6.1.4.1.1991.1.1.4.14.1.1.5',
      snL4WebCacheRowStatus => '1.3.6.1.4.1.1991.1.1.4.14.1.1.6',
      snL4WebCacheDeleteState => '1.3.6.1.4.1.1991.1.1.4.14.1.1.7',
      snL4WebCacheGroup => '1.3.6.1.4.1.1991.1.1.4.15',
      snL4WebCacheGroupTable => '1.3.6.1.4.1.1991.1.1.4.15.1',
      snL4WebCacheGroupEntry => '1.3.6.1.4.1.1991.1.1.4.15.1.1',
      snL4WebCacheGroupId => '1.3.6.1.4.1.1991.1.1.4.15.1.1.1',
      snL4WebCacheGroupName => '1.3.6.1.4.1.1991.1.1.4.15.1.1.2',
      snL4WebCacheGroupWebCacheIpList => '1.3.6.1.4.1.1991.1.1.4.15.1.1.3',
      snL4WebCacheGroupDestMask => '1.3.6.1.4.1.1991.1.1.4.15.1.1.4',
      snL4WebCacheGroupSrcMask => '1.3.6.1.4.1.1991.1.1.4.15.1.1.5',
      snL4WebCacheGroupAdminStatus => '1.3.6.1.4.1.1991.1.1.4.15.1.1.6',
      snL4WebCacheGroupRowStatus => '1.3.6.1.4.1.1991.1.1.4.15.1.1.7',
      snL4WebCacheTrafficStats => '1.3.6.1.4.1.1991.1.1.4.16',
      snL4WebCacheTrafficStatsTable => '1.3.6.1.4.1.1991.1.1.4.16.1',
      snL4WebCacheTrafficStatsEntry => '1.3.6.1.4.1.1991.1.1.4.16.1.1',
      snL4WebCacheTrafficIp => '1.3.6.1.4.1.1991.1.1.4.16.1.1.1',
      snL4WebCacheTrafficPort => '1.3.6.1.4.1.1991.1.1.4.16.1.1.2',
      snL4WebCacheCurrConnections => '1.3.6.1.4.1.1991.1.1.4.16.1.1.3',
      snL4WebCacheTotalConnections => '1.3.6.1.4.1.1991.1.1.4.16.1.1.4',
      snL4WebCacheTxPkts => '1.3.6.1.4.1.1991.1.1.4.16.1.1.5',
      snL4WebCacheRxPkts => '1.3.6.1.4.1.1991.1.1.4.16.1.1.6',
      snL4WebCacheTxOctets => '1.3.6.1.4.1.1991.1.1.4.16.1.1.7',
      snL4WebCacheRxOctets => '1.3.6.1.4.1.1991.1.1.4.16.1.1.8',
      snL4WebCachePortState => '1.3.6.1.4.1.1991.1.1.4.16.1.1.9',
      snL4WebUncachedTrafficStats => '1.3.6.1.4.1.1991.1.1.4.17',
      snL4WebUncachedTrafficStatsTable => '1.3.6.1.4.1.1991.1.1.4.17.1',
      snL4WebUncachedTrafficStatsEntry => '1.3.6.1.4.1.1991.1.1.4.17.1.1',
      snL4WebServerPort => '1.3.6.1.4.1.1991.1.1.4.17.1.1.1',
      snL4WebClientPort => '1.3.6.1.4.1.1991.1.1.4.17.1.1.2',
      snL4WebUncachedTxPkts => '1.3.6.1.4.1.1991.1.1.4.17.1.1.3',
      snL4WebUncachedRxPkts => '1.3.6.1.4.1.1991.1.1.4.17.1.1.4',
      snL4WebUncachedTxOctets => '1.3.6.1.4.1.1991.1.1.4.17.1.1.5',
      snL4WebUncachedRxOctets => '1.3.6.1.4.1.1991.1.1.4.17.1.1.6',
      snL4WebServerPortName => '1.3.6.1.4.1.1991.1.1.4.17.1.1.7',
      snL4WebClientPortName => '1.3.6.1.4.1.1991.1.1.4.17.1.1.8',
      snL4WebCachePort => '1.3.6.1.4.1.1991.1.1.4.18',
      snL4WebCachePortTable => '1.3.6.1.4.1.1991.1.1.4.18.1',
      snL4WebCachePortEntry => '1.3.6.1.4.1.1991.1.1.4.18.1.1',
      snL4WebCachePortServerIp => '1.3.6.1.4.1.1991.1.1.4.18.1.1.1',
      snL4WebCachePortPort => '1.3.6.1.4.1.1991.1.1.4.18.1.1.2',
      snL4WebCachePortAdminStatus => '1.3.6.1.4.1.1991.1.1.4.18.1.1.3',
      snL4WebCachePortRowStatus => '1.3.6.1.4.1.1991.1.1.4.18.1.1.4',
      snL4WebCachePortDeleteState => '1.3.6.1.4.1.1991.1.1.4.18.1.1.5',
      snL4RealServerCfg => '1.3.6.1.4.1.1991.1.1.4.19',
      snL4RealServerCfgTable => '1.3.6.1.4.1.1991.1.1.4.19.1',
      snL4RealServerCfgEntry => '1.3.6.1.4.1.1991.1.1.4.19.1.1',
      snL4RealServerCfgIP => '1.3.6.1.4.1.1991.1.1.4.19.1.1.1',
      snL4RealServerCfgName => '1.3.6.1.4.1.1991.1.1.4.19.1.1.2',
      snL4RealServerCfgAdminStatus => '1.3.6.1.4.1.1991.1.1.4.19.1.1.3',
      snL4RealServerCfgMaxConnections => '1.3.6.1.4.1.1991.1.1.4.19.1.1.4',
      snL4RealServerCfgWeight => '1.3.6.1.4.1.1991.1.1.4.19.1.1.5',
      snL4RealServerCfgRowStatus => '1.3.6.1.4.1.1991.1.1.4.19.1.1.6',
      snL4RealServerCfgDeleteState => '1.3.6.1.4.1.1991.1.1.4.19.1.1.7',
      snL4RealServerPortCfg => '1.3.6.1.4.1.1991.1.1.4.20',
      snL4RealServerPortCfgTable => '1.3.6.1.4.1.1991.1.1.4.20.1',
      snL4RealServerPortCfgEntry => '1.3.6.1.4.1.1991.1.1.4.20.1.1',
      snL4RealServerPortCfgIP => '1.3.6.1.4.1.1991.1.1.4.20.1.1.1',
      snL4RealServerPortCfgPort => '1.3.6.1.4.1.1991.1.1.4.20.1.1.3',
      snL4RealServerPortCfgServerName => '1.3.6.1.4.1.1991.1.1.4.20.1.1.2',
      snL4RealServerPortCfgAdminStatus => '1.3.6.1.4.1.1991.1.1.4.20.1.1.4',
      snL4RealServerPortCfgRowStatus => '1.3.6.1.4.1.1991.1.1.4.20.1.1.5',
      snL4RealServerPortCfgDeleteState => '1.3.6.1.4.1.1991.1.1.4.20.1.1.6',
      snL4VirtualServerCfg => '1.3.6.1.4.1.1991.1.1.4.21',
      snL4VirtualServerCfgTable => '1.3.6.1.4.1.1991.1.1.4.21.1',
      snL4VirtualServerCfgEntry => '1.3.6.1.4.1.1991.1.1.4.21.1.1',
      snL4VirtualServerCfgVirtualIP => '1.3.6.1.4.1.1991.1.1.4.21.1.1.1',
      snL4VirtualServerCfgName => '1.3.6.1.4.1.1991.1.1.4.21.1.1.2',
      snL4VirtualServerCfgAdminStatus => '1.3.6.1.4.1.1991.1.1.4.21.1.1.3',
      snL4VirtualServerCfgSDAType => '1.3.6.1.4.1.1991.1.1.4.21.1.1.4',
      snL4VirtualServerCfgRowStatus => '1.3.6.1.4.1.1991.1.1.4.21.1.1.5',
      snL4VirtualServerCfgDeleteState => '1.3.6.1.4.1.1991.1.1.4.21.1.1.6',
      snL4VirtualServerPortCfg => '1.3.6.1.4.1.1991.1.1.4.22',
      snL4VirtualServerPortCfgTable => '1.3.6.1.4.1.1991.1.1.4.22.1',
      snL4VirtualServerPortCfgEntry => '1.3.6.1.4.1.1991.1.1.4.22.1.1',
      snL4VirtualServerPortCfgIP => '1.3.6.1.4.1.1991.1.1.4.22.1.1.1',
      snL4VirtualServerPortCfgPort => '1.3.6.1.4.1.1991.1.1.4.22.1.1.2',
      snL4VirtualServerPortCfgServerName => '1.3.6.1.4.1.1991.1.1.4.22.1.1.3',
      snL4VirtualServerPortCfgAdminStatus => '1.3.6.1.4.1.1991.1.1.4.22.1.1.4',
      snL4VirtualServerPortCfgSticky => '1.3.6.1.4.1.1991.1.1.4.22.1.1.5',
      snL4VirtualServerPortCfgConcurrent => '1.3.6.1.4.1.1991.1.1.4.22.1.1.6',
      snL4VirtualServerPortCfgRowStatus => '1.3.6.1.4.1.1991.1.1.4.22.1.1.7',
      snL4VirtualServerPortCfgDeleteState => '1.3.6.1.4.1.1991.1.1.4.22.1.1.8',
      snL4VirtualServerStatistic => '1.3.6.1.4.1.1991.1.1.4.25',
      snL4VirtualServerStatisticTable => '1.3.6.1.4.1.1991.1.1.4.25.1',
      snL4VirtualServerStatisticEntry => '1.3.6.1.4.1.1991.1.1.4.25.1.1',
      snL4VirtualServerStatisticIP => '1.3.6.1.4.1.1991.1.1.4.25.1.1.1',
      snL4VirtualServerStatisticName => '1.3.6.1.4.1.1991.1.1.4.25.1.1.2',
      snL4VirtualServerStatisticReceivePkts => '1.3.6.1.4.1.1991.1.1.4.25.1.1.3',
      snL4VirtualServerStatisticTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.25.1.1.4',
      snL4VirtualServerStatisticTotalConnections => '1.3.6.1.4.1.1991.1.1.4.25.1.1.5',
      snL4VirtualServerStatisticReceiveBytes => '1.3.6.1.4.1.1991.1.1.4.25.1.1.6',
      snL4VirtualServerStatisticTransmitBytes => '1.3.6.1.4.1.1991.1.1.4.25.1.1.7',
      snL4VirtualServerStatisticSymmetricState => '1.3.6.1.4.1.1991.1.1.4.25.1.1.8',
      snL4VirtualServerStatisticSymmetricPriority => '1.3.6.1.4.1.1991.1.1.4.25.1.1.9',
      snL4VirtualServerStatisticSymmetricKeep => '1.3.6.1.4.1.1991.1.1.4.25.1.1.10',
      snL4VirtualServerStatisticSymmetricActivates => '1.3.6.1.4.1.1991.1.1.4.25.1.1.11',
      snL4VirtualServerStatisticSymmetricInactives => '1.3.6.1.4.1.1991.1.1.4.25.1.1.12',
      snL4VirtualServerStatisticSymmetricBestStandbyMacAddr => '1.3.6.1.4.1.1991.1.1.4.25.1.1.13',
      snL4VirtualServerStatisticSymmetricActiveMacAddr => '1.3.6.1.4.1.1991.1.1.4.25.1.1.14',
      snL4RealServerStatistic => '1.3.6.1.4.1.1991.1.1.4.23',
      snL4RealServerStatisticTable => '1.3.6.1.4.1.1991.1.1.4.23.1',
      snL4RealServerStatisticEntry => '1.3.6.1.4.1.1991.1.1.4.23.1.1',
      snL4RealServerStatisticRealIP => '1.3.6.1.4.1.1991.1.1.4.23.1.1.1',
      snL4RealServerStatisticName => '1.3.6.1.4.1.1991.1.1.4.23.1.1.2',
      snL4RealServerStatisticReceivePkts => '1.3.6.1.4.1.1991.1.1.4.23.1.1.3',
      snL4RealServerStatisticTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.23.1.1.4',
      snL4RealServerStatisticCurConnections => '1.3.6.1.4.1.1991.1.1.4.23.1.1.5',
      snL4RealServerStatisticTotalConnections => '1.3.6.1.4.1.1991.1.1.4.23.1.1.6',
      snL4RealServerStatisticAge => '1.3.6.1.4.1.1991.1.1.4.23.1.1.7',
      snL4RealServerStatisticState => '1.3.6.1.4.1.1991.1.1.4.23.1.1.8',
      snL4RealServerStatisticStateDefinition => {
          0 => 'serverdisabled',
          1 => 'serverenabled',
          2 => 'serverfailed',
          3 => 'servertesting',
          4 => 'serversuspect',
          5 => 'servershutdown',
          6 => 'serveractive',
      },
      snL4RealServerStatisticReassignments => '1.3.6.1.4.1.1991.1.1.4.23.1.1.9',
      snL4RealServerStatisticReassignmentLimit => '1.3.6.1.4.1.1991.1.1.4.23.1.1.10',
      snL4RealServerStatisticFailedPortExists => '1.3.6.1.4.1.1991.1.1.4.23.1.1.11',
      snL4RealServerStatisticFailTime => '1.3.6.1.4.1.1991.1.1.4.23.1.1.12',
      snL4RealServerStatisticPeakConnections => '1.3.6.1.4.1.1991.1.1.4.23.1.1.13',
      snL4VirtualServerPortStatistic => '1.3.6.1.4.1.1991.1.1.4.26',
      snL4VirtualServerPortStatisticTable => '1.3.6.1.4.1.1991.1.1.4.26.1',
      snL4VirtualServerPortStatisticEntry => '1.3.6.1.4.1.1991.1.1.4.26.1.1',
      snL4VirtualServerPortStatisticIP => '1.3.6.1.4.1.1991.1.1.4.26.1.1.1',
      snL4VirtualServerPortStatisticPort => '1.3.6.1.4.1.1991.1.1.4.26.1.1.2',
      snL4VirtualServerPortStatisticServerName => '1.3.6.1.4.1.1991.1.1.4.26.1.1.3',
      snL4VirtualServerPortStatisticCurrentConnection => '1.3.6.1.4.1.1991.1.1.4.26.1.1.4',
      snL4VirtualServerPortStatisticTotalConnection => '1.3.6.1.4.1.1991.1.1.4.26.1.1.5',
      snL4VirtualServerPortStatisticPeakConnection => '1.3.6.1.4.1.1991.1.1.4.26.1.1.6',
      snL4RealServerPortStatistic => '1.3.6.1.4.1.1991.1.1.4.24',
      snL4RealServerPortStatisticTable => '1.3.6.1.4.1.1991.1.1.4.24.1',
      snL4RealServerPortStatisticEntry => '1.3.6.1.4.1.1991.1.1.4.24.1.1',
      snL4RealServerPortStatisticIP => '1.3.6.1.4.1.1991.1.1.4.24.1.1.1',
      snL4RealServerPortStatisticPort => '1.3.6.1.4.1.1991.1.1.4.24.1.1.2',
      snL4RealServerPortStatisticServerName => '1.3.6.1.4.1.1991.1.1.4.24.1.1.3',
      snL4RealServerPortStatisticReassignCount => '1.3.6.1.4.1.1991.1.1.4.24.1.1.4',
      snL4RealServerPortStatisticState => '1.3.6.1.4.1.1991.1.1.4.24.1.1.5',
      snL4RealServerPortStatisticStateDefinition => {
          0 => 'disabled',
          1 => 'enabled',
          2 => 'failed',
          3 => 'testing',
          4 => 'suspect',
          5 => 'shutdown',
          6 => 'active',
          7 => 'unbound',
          8 => 'awaitUnbind',
          9 => 'awaitDelete',
      },
      snL4RealServerPortStatisticFailTime => '1.3.6.1.4.1.1991.1.1.4.24.1.1.6',
      snL4RealServerPortStatisticCurrentConnection => '1.3.6.1.4.1.1991.1.1.4.24.1.1.7',
      snL4RealServerPortStatisticTotalConnection => '1.3.6.1.4.1.1991.1.1.4.24.1.1.8',
      snL4RealServerPortStatisticRxPkts => '1.3.6.1.4.1.1991.1.1.4.24.1.1.9',
      snL4RealServerPortStatisticTxPkts => '1.3.6.1.4.1.1991.1.1.4.24.1.1.10',
      snL4RealServerPortStatisticRxBytes => '1.3.6.1.4.1.1991.1.1.4.24.1.1.11',
      snL4RealServerPortStatisticTxBytes => '1.3.6.1.4.1.1991.1.1.4.24.1.1.12',
      snL4RealServerPortStatisticPeakConnection => '1.3.6.1.4.1.1991.1.1.4.24.1.1.13',
      snL4GslbSiteRemoteServerIrons => '1.3.6.1.4.1.1991.1.1.4.27',
      snL4GslbSiteRemoteServerIronTable => '1.3.6.1.4.1.1991.1.1.4.27.1',
      snL4GslbSiteRemoteServerIronEntry => '1.3.6.1.4.1.1991.1.1.4.27.1.1',
      snL4GslbSiteRemoteServerIronIP => '1.3.6.1.4.1.1991.1.1.4.27.1.1.1',
      snL4GslbSiteRemoteServerIronPreference => '1.3.6.1.4.1.1991.1.1.4.27.1.1.2',
      snL4History => '1.3.6.1.4.1.1991.1.1.4.28',
      snL4RealServerHistoryControlTable => '1.3.6.1.4.1.1991.1.1.4.28.1',
      snL4RealServerHistoryControlEntry => '1.3.6.1.4.1.1991.1.1.4.28.1.1',
      snL4RealServerHistoryControlIndex => '1.3.6.1.4.1.1991.1.1.4.28.1.1.1',
      snL4RealServerHistoryControlDataSource => '1.3.6.1.4.1.1991.1.1.4.28.1.1.2',
      snL4RealServerHistoryControlBucketsRequested => '1.3.6.1.4.1.1991.1.1.4.28.1.1.3',
      snL4RealServerHistoryControlBucketsGranted => '1.3.6.1.4.1.1991.1.1.4.28.1.1.4',
      snL4RealServerHistoryControlInterval => '1.3.6.1.4.1.1991.1.1.4.28.1.1.5',
      snL4RealServerHistoryControlOwner => '1.3.6.1.4.1.1991.1.1.4.28.1.1.6',
      snL4RealServerHistoryControlStatus => '1.3.6.1.4.1.1991.1.1.4.28.1.1.7',
      snL4RealServerHistoryTable => '1.3.6.1.4.1.1991.1.1.4.28.2',
      snL4RealServerHistoryEntry => '1.3.6.1.4.1.1991.1.1.4.28.2.1',
      snL4RealServerHistoryIndex => '1.3.6.1.4.1.1991.1.1.4.28.2.1.1',
      snL4RealServerHistorySampleIndex => '1.3.6.1.4.1.1991.1.1.4.28.2.1.2',
      snL4RealServerHistoryIntervalStart => '1.3.6.1.4.1.1991.1.1.4.28.2.1.3',
      snL4RealServerHistoryReceivePkts => '1.3.6.1.4.1.1991.1.1.4.28.2.1.4',
      snL4RealServerHistoryTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.28.2.1.5',
      snL4RealServerHistoryTotalConnections => '1.3.6.1.4.1.1991.1.1.4.28.2.1.6',
      snL4RealServerHistoryCurConnections => '1.3.6.1.4.1.1991.1.1.4.28.2.1.7',
      snL4RealServerHistoryPeakConnections => '1.3.6.1.4.1.1991.1.1.4.28.2.1.8',
      snL4RealServerHistoryReassignments => '1.3.6.1.4.1.1991.1.1.4.28.2.1.9',
      snL4RealServerPortHistoryControlTable => '1.3.6.1.4.1.1991.1.1.4.28.3',
      snL4RealServerPortHistoryControlEntry => '1.3.6.1.4.1.1991.1.1.4.28.3.1',
      snL4RealServerPortHistoryControlIndex => '1.3.6.1.4.1.1991.1.1.4.28.3.1.1',
      snL4RealServerPortHistoryControlDataSource => '1.3.6.1.4.1.1991.1.1.4.28.3.1.2',
      snL4RealServerPortHistoryControlBucketsRequested => '1.3.6.1.4.1.1991.1.1.4.28.3.1.3',
      snL4RealServerPortHistoryControlBucketsGranted => '1.3.6.1.4.1.1991.1.1.4.28.3.1.4',
      snL4RealServerPortHistoryControlInterval => '1.3.6.1.4.1.1991.1.1.4.28.3.1.5',
      snL4RealServerPortHistoryControlOwner => '1.3.6.1.4.1.1991.1.1.4.28.3.1.6',
      snL4RealServerPortHistoryControlStatus => '1.3.6.1.4.1.1991.1.1.4.28.3.1.7',
      snL4RealServerPortHistoryTable => '1.3.6.1.4.1.1991.1.1.4.28.4',
      snL4RealServerPortHistoryEntry => '1.3.6.1.4.1.1991.1.1.4.28.4.1',
      snL4RealServerPortHistoryIndex => '1.3.6.1.4.1.1991.1.1.4.28.4.1.1',
      snL4RealServerPortHistorySampleIndex => '1.3.6.1.4.1.1991.1.1.4.28.4.1.2',
      snL4RealServerPortHistoryIntervalStart => '1.3.6.1.4.1.1991.1.1.4.28.4.1.3',
      snL4RealServerPortHistoryReceivePkts => '1.3.6.1.4.1.1991.1.1.4.28.4.1.4',
      snL4RealServerPortHistoryTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.28.4.1.5',
      snL4RealServerPortHistoryTotalConnections => '1.3.6.1.4.1.1991.1.1.4.28.4.1.6',
      snL4RealServerPortHistoryCurConnections => '1.3.6.1.4.1.1991.1.1.4.28.4.1.7',
      snL4RealServerPortHistoryPeakConnections => '1.3.6.1.4.1.1991.1.1.4.28.4.1.8',
      snL4RealServerPortHistoryResponseTime => '1.3.6.1.4.1.1991.1.1.4.28.4.1.9',
      snL4VirtualServerHistoryControlTable => '1.3.6.1.4.1.1991.1.1.4.28.5',
      snL4VirtualServerHistoryControlEntry => '1.3.6.1.4.1.1991.1.1.4.28.5.1',
      snL4VirtualServerHistoryControlIndex => '1.3.6.1.4.1.1991.1.1.4.28.5.1.1',
      snL4VirtualServerHistoryControlDataSource => '1.3.6.1.4.1.1991.1.1.4.28.5.1.2',
      snL4VirtualServerHistoryControlBucketsRequested => '1.3.6.1.4.1.1991.1.1.4.28.5.1.3',
      snL4VirtualServerHistoryControlBucketsGranted => '1.3.6.1.4.1.1991.1.1.4.28.5.1.4',
      snL4VirtualServerHistoryControlInterval => '1.3.6.1.4.1.1991.1.1.4.28.5.1.5',
      snL4VirtualServerHistoryControlOwner => '1.3.6.1.4.1.1991.1.1.4.28.5.1.6',
      snL4VirtualServerHistoryControlStatus => '1.3.6.1.4.1.1991.1.1.4.28.5.1.7',
      snL4VirtualServerHistoryTable => '1.3.6.1.4.1.1991.1.1.4.28.6',
      snL4VirtualServerHistoryEntry => '1.3.6.1.4.1.1991.1.1.4.28.6.1',
      snL4VirtualServerHistoryIndex => '1.3.6.1.4.1.1991.1.1.4.28.6.1.1',
      snL4VirtualServerHistorySampleIndex => '1.3.6.1.4.1.1991.1.1.4.28.6.1.2',
      snL4VirtualServerHistoryIntervalStart => '1.3.6.1.4.1.1991.1.1.4.28.6.1.3',
      snL4VirtualServerHistoryReceivePkts => '1.3.6.1.4.1.1991.1.1.4.28.6.1.4',
      snL4VirtualServerHistoryTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.28.6.1.5',
      snL4VirtualServerHistoryTotalConnections => '1.3.6.1.4.1.1991.1.1.4.28.6.1.6',
      snL4VirtualServerHistoryCurConnections => '1.3.6.1.4.1.1991.1.1.4.28.6.1.7',
      snL4VirtualServerHistoryPeakConnections => '1.3.6.1.4.1.1991.1.1.4.28.6.1.8',
      snL4VirtualServerPortHistoryControlTable => '1.3.6.1.4.1.1991.1.1.4.28.7',
      snL4VirtualServerPortHistoryControlEntry => '1.3.6.1.4.1.1991.1.1.4.28.7.1',
      snL4VirtualServerPortHistoryControlIndex => '1.3.6.1.4.1.1991.1.1.4.28.7.1.1',
      snL4VirtualServerPortHistoryControlDataSource => '1.3.6.1.4.1.1991.1.1.4.28.7.1.2',
      snL4VirtualServerPortHistoryControlBucketsRequested => '1.3.6.1.4.1.1991.1.1.4.28.7.1.3',
      snL4VirtualServerPortHistoryControlBucketsGranted => '1.3.6.1.4.1.1991.1.1.4.28.7.1.4',
      snL4VirtualServerPortHistoryControlInterval => '1.3.6.1.4.1.1991.1.1.4.28.7.1.5',
      snL4VirtualServerPortHistoryControlOwner => '1.3.6.1.4.1.1991.1.1.4.28.7.1.6',
      snL4VirtualServerPortHistoryControlStatus => '1.3.6.1.4.1.1991.1.1.4.28.7.1.7',
      snL4VirtualServerPortHistoryTable => '1.3.6.1.4.1.1991.1.1.4.28.8',
      snL4VirtualServerPortHistoryEntry => '1.3.6.1.4.1.1991.1.1.4.28.8.1',
      snL4VirtualServerPortHistoryIndex => '1.3.6.1.4.1.1991.1.1.4.28.8.1.1',
      snL4VirtualServerPortHistorySampleIndex => '1.3.6.1.4.1.1991.1.1.4.28.8.1.2',
      snL4VirtualServerPortHistoryIntervalStart => '1.3.6.1.4.1.1991.1.1.4.28.8.1.3',
      snL4VirtualServerPortHistoryReceivePkts => '1.3.6.1.4.1.1991.1.1.4.28.8.1.4',
      snL4VirtualServerPortHistoryTransmitPkts => '1.3.6.1.4.1.1991.1.1.4.28.8.1.5',
      snL4VirtualServerPortHistoryTotalConnections => '1.3.6.1.4.1.1991.1.1.4.28.8.1.6',
      snL4VirtualServerPortHistoryCurConnections => '1.3.6.1.4.1.1991.1.1.4.28.8.1.7',
      snL4VirtualServerPortHistoryPeakConnections => '1.3.6.1.4.1.1991.1.1.4.28.8.1.8',
  },
  'JUNIPER-IVE-MIB' => {
      logFullPercent => '1.3.6.1.4.1.12532.1.0',
      signedInWebUsers => '1.3.6.1.4.1.12532.2.0',
      signedInMailUsers => '1.3.6.1.4.1.12532.3.0',
      blockedIP => '1.3.6.1.4.1.12532.4.0',
      authServerName => '1.3.6.1.4.1.12532.5.0',
      productName => '1.3.6.1.4.1.12532.6.0',
      productVersion => '1.3.6.1.4.1.12532.7.0',
      fileName => '1.3.6.1.4.1.12532.8.0',
      meetingUserCount => '1.3.6.1.4.1.12532.9.0',
      iveCpuUtil => '1.3.6.1.4.1.12532.10.0',
      iveMemoryUtil => '1.3.6.1.4.1.12532.11.0',
      iveConcurrentUsers => '1.3.6.1.4.1.12532.12.0',
      clusterConcurrentUsers => '1.3.6.1.4.1.12532.13.0',
      iveTotalHits => '1.3.6.1.4.1.12532.14.0',
      iveFileHits => '1.3.6.1.4.1.12532.15.0',
      iveWebHits => '1.3.6.1.4.1.12532.16.0',
      iveAppletHits => '1.3.6.1.4.1.12532.17.0',
      ivetermHits => '1.3.6.1.4.1.12532.18.0',
      iveSAMHits => '1.3.6.1.4.1.12532.19.0',
      iveNCHits => '1.3.6.1.4.1.12532.20.0',
      meetingHits => '1.3.6.1.4.1.12532.21.0',
      meetingCount => '1.3.6.1.4.1.12532.22.0',
      logName => '1.3.6.1.4.1.12532.23.0',
      iveSwapUtil => '1.3.6.1.4.1.12532.24.0',
      diskFullPercent => '1.3.6.1.4.1.12532.25.0',
      logID => '1.3.6.1.4.1.12532.27.0',
      logType => '1.3.6.1.4.1.12532.28.0',
      logDescription => '1.3.6.1.4.1.12532.29.0',
      ivsName => '1.3.6.1.4.1.12532.30.0',
      ocspResponderURL => '1.3.6.1.4.1.12532.31.0',
      fanDescription => '1.3.6.1.4.1.12532.32.0',
      psDescription => '1.3.6.1.4.1.12532.33.0',
      raidDescription => '1.3.6.1.4.1.12532.34.0',
      clusterName => '1.3.6.1.4.1.12532.35.0',
      nodeList => '1.3.6.1.4.1.12532.36.0',
      vipType => '1.3.6.1.4.1.12532.37.0',
      currentVIP => '1.3.6.1.4.1.12532.38.0',
      newVIP => '1.3.6.1.4.1.12532.39.0',
      nicEvent => '1.3.6.1.4.1.12532.40.0',
      nodeName => '1.3.6.1.4.1.12532.41.0',
      iveTemperature => '1.3.6.1.4.1.12532.42.0',
      iveVPNTunnels => '1.3.6.1.4.1.12532.43.0',
      iveSSLConnections => '1.3.6.1.4.1.12532.44.0',
  },
  'BGP4-MIB' => {
      bgpVersion => '1.3.6.1.2.1.15.1.0',
      bgpLocalAs => '1.3.6.1.2.1.15.2.0',
      bgpPeerTable => '1.3.6.1.2.1.15.3',
      bgpPeerEntry => '1.3.6.1.2.1.15.3.1',
      bgpPeerIdentifier => '1.3.6.1.2.1.15.3.1.1',
      bgpPeerState => '1.3.6.1.2.1.15.3.1.2',
      bgpPeerStateDefinition => {
        1 => 'idle',
        2 => 'connect',
        3 => 'active',
        4 => 'opensent',
        5 => 'openconfirm',
        6 => 'established',
      },
      bgpPeerAdminStatus => '1.3.6.1.2.1.15.3.1.3',
      bgpPeerAdminStatusDefinition => {
        1 => 'stop',
        2 => 'start',
      },
      bgpPeerNegotiatedVersion => '1.3.6.1.2.1.15.3.1.4',
      bgpPeerLocalAddr => '1.3.6.1.2.1.15.3.1.5',
      bgpPeerLocalPort => '1.3.6.1.2.1.15.3.1.6',
      bgpPeerRemoteAddr => '1.3.6.1.2.1.15.3.1.7',
      bgpPeerRemotePort => '1.3.6.1.2.1.15.3.1.8',
      bgpPeerRemoteAs => '1.3.6.1.2.1.15.3.1.9',
      bgpPeerInUpdates => '1.3.6.1.2.1.15.3.1.10',
      bgpPeerOutUpdates => '1.3.6.1.2.1.15.3.1.11',
      bgpPeerInTotalMessages => '1.3.6.1.2.1.15.3.1.12',
      bgpPeerOutTotalMessages => '1.3.6.1.2.1.15.3.1.13',
      bgpPeerLastError => '1.3.6.1.2.1.15.3.1.14',
      bgpPeerFsmEstablishedTransitions => '1.3.6.1.2.1.15.3.1.15',
      bgpPeerFsmEstablishedTime => '1.3.6.1.2.1.15.3.1.16',
      bgpPeerConnectRetryInterval => '1.3.6.1.2.1.15.3.1.17',
      bgpPeerHoldTime => '1.3.6.1.2.1.15.3.1.18',
      bgpPeerKeepAlive => '1.3.6.1.2.1.15.3.1.19',
      bgpPeerHoldTimeConfigured => '1.3.6.1.2.1.15.3.1.20',
      bgpPeerKeepAliveConfigured => '1.3.6.1.2.1.15.3.1.21',
      bgpPeerMinASOriginationInterval => '1.3.6.1.2.1.15.3.1.22',
      bgpPeerMinRouteAdvertisementInterval => '1.3.6.1.2.1.15.3.1.23',
      bgpPeerInUpdateElapsedTime => '1.3.6.1.2.1.15.3.1.24',
  },
  'FORTINET-FORTIGATE-MIB' => {
      fgSystem => '1.3.6.1.4.1.12356.101.4',
      fgSystemInfo => '1.3.6.1.4.1.12356.101.4.1',
      fgSysVersion => '1.3.6.1.4.1.12356.101.4.1.1.0',
      fgSysMgmtVdom => '1.3.6.1.4.1.12356.101.4.1.2.0',
      fgSysCpuUsage => '1.3.6.1.4.1.12356.101.4.1.3.0',
      fgSysMemUsage => '1.3.6.1.4.1.12356.101.4.1.4.0',
      fgSysMemCapacity => '1.3.6.1.4.1.12356.101.4.1.5.0',
      fgSysDiskUsage => '1.3.6.1.4.1.12356.101.4.1.6.0',
      fgSysDiskCapacity => '1.3.6.1.4.1.12356.101.4.1.7.0',
      fgSysSesCount => '1.3.6.1.4.1.12356.101.4.1.8.0',
      fgSoftware => '1.3.6.1.4.1.12356.101.4.2',
      fgSoftware => '1.3.6.1.4.1.12356.101.4.2',
      fgSysVersionAv => '1.3.6.1.4.1.12356.101.4.2.1.0',
      fgSysVersionIps => '1.3.6.1.4.1.12356.101.4.2.2.0',
      fgHwSensors => '1.3.6.1.4.1.12356.101.4.3',
      fgHwSensors => '1.3.6.1.4.1.12356.101.4.3',
      fgHwSensorCount => '1.3.6.1.4.1.12356.101.4.3.1.0',
      fgHwSensorTable => '1.3.6.1.4.1.12356.101.4.3.2',
      fgHwSensorEntry => '1.3.6.1.4.1.12356.101.4.3.2.1',
      fgHwSensorEntIndex => '1.3.6.1.4.1.12356.101.4.3.2.1.1',
      fgHwSensorEntName => '1.3.6.1.4.1.12356.101.4.3.2.1.2',
      fgHwSensorEntValue => '1.3.6.1.4.1.12356.101.4.3.2.1.3',
      fgHwSensorEntAlarmStatus => '1.3.6.1.4.1.12356.101.4.3.2.1.4',
      fgHwSensorEntAlarmStatusDefinition => {
        0 => 'false',
        1 => 'true',
      },
      fgFirewall => '1.3.6.1.4.1.12356.101.5',
      fgFwPolicies => '1.3.6.1.4.1.12356.101.5.1',
      fgFwPolInfo => '1.3.6.1.4.1.12356.101.5.1.1',
      fgFwPolTables => '1.3.6.1.4.1.12356.101.5.1.2',
      fgFwPolTables => '1.3.6.1.4.1.12356.101.5.1.2',
      fgFwPolStatsTable => '1.3.6.1.4.1.12356.101.5.1.2.1',
      fgFwPolStatsEntry => '1.3.6.1.4.1.12356.101.5.1.2.1.1',
      fgFwPolID => '1.3.6.1.4.1.12356.101.5.1.2.1.1.1',
      fgFwPolPktCount => '1.3.6.1.4.1.12356.101.5.1.2.1.1.2',
      fgFwPolByteCount => '1.3.6.1.4.1.12356.101.5.1.2.1.1.3',
      fgFwUsers => '1.3.6.1.4.1.12356.101.5.2',
      fgFwUserInfo => '1.3.6.1.4.1.12356.101.5.2.1',
      fgFwUserInfo => '1.3.6.1.4.1.12356.101.5.2.1',
      fgFwUserNumber => '1.3.6.1.4.1.12356.101.5.2.1.1.0',
      fgFwUserAuthTimeout => '1.3.6.1.4.1.12356.101.5.2.1.2.0',
      fgFwUserTables => '1.3.6.1.4.1.12356.101.5.2.2',
      fgFwUserTables => '1.3.6.1.4.1.12356.101.5.2.2',
      fgFwUserTable => '1.3.6.1.4.1.12356.101.5.2.2.1',
      fgFwUserEntry => '1.3.6.1.4.1.12356.101.5.2.2.1.1',
      fgFwUserIndex => '1.3.6.1.4.1.12356.101.5.2.2.1.1.1',
      fgFwUserName => '1.3.6.1.4.1.12356.101.5.2.2.1.1.2',
      fgFwUserAuth => '1.3.6.1.4.1.12356.101.5.2.2.1.1.3',
      fgFwUserState => '1.3.6.1.4.1.12356.101.5.2.2.1.1.4',
      fgFwUserVdom => '1.3.6.1.4.1.12356.101.5.2.2.1.1.5',
      fgMgmt => '1.3.6.1.4.1.12356.101.6',
      fgFmTrapPrefix => '1.3.6.1.4.1.12356.101.6.0',
      fgAdmin => '1.3.6.1.4.1.12356.101.6.1',
      fgAdminOptions => '1.3.6.1.4.1.12356.101.6.1.1',
      fgAdminOptions => '1.3.6.1.4.1.12356.101.6.1.1',
      fgAdminIdleTimeout => '1.3.6.1.4.1.12356.101.6.1.1.1.0',
      fgAdminLcdProtection => '1.3.6.1.4.1.12356.101.6.1.1.2.0',
      fgAdminTables => '1.3.6.1.4.1.12356.101.6.1.2',
      fgAdminTables => '1.3.6.1.4.1.12356.101.6.1.2',
      fgAdminTable => '1.3.6.1.4.1.12356.101.6.1.2.1',
      fgAdminEntry => '1.3.6.1.4.1.12356.101.6.1.2.1.1',
      fgAdminVdom => '1.3.6.1.4.1.12356.101.6.1.2.1.1.1',
      fgMgmtTrapObjects => '1.3.6.1.4.1.12356.101.6.2',
      fgMgmtTrapObjects => '1.3.6.1.4.1.12356.101.6.2',
      fgManIfIp => '1.3.6.1.4.1.12356.101.6.2.1.0',
      fgManIfMask => '1.3.6.1.4.1.12356.101.6.2.2.0',
      fgIntf => '1.3.6.1.4.1.12356.101.7',
      fgIntfInfo => '1.3.6.1.4.1.12356.101.7.1',
      fgIntfTables => '1.3.6.1.4.1.12356.101.7.2',
      fgIntfTables => '1.3.6.1.4.1.12356.101.7.2',
      fgIntfTable => '1.3.6.1.4.1.12356.101.7.2.1',
      fgIntfEntry => '1.3.6.1.4.1.12356.101.7.2.1.1',
      fgIntfEntVdom => '1.3.6.1.4.1.12356.101.7.2.1.1.1',
      fgAntivirus => '1.3.6.1.4.1.12356.101.8',
      fgAvInfo => '1.3.6.1.4.1.12356.101.8.1',
      fgAvTables => '1.3.6.1.4.1.12356.101.8.2',
      fgAvTables => '1.3.6.1.4.1.12356.101.8.2',
      fgAvStatsTable => '1.3.6.1.4.1.12356.101.8.2.1',
      fgAvStatsEntry => '1.3.6.1.4.1.12356.101.8.2.1.1',
      fgAvVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.1',
      fgAvVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.2',
      fgAvHTTPVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.3',
      fgAvHTTPVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.4',
      fgAvSMTPVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.5',
      fgAvSMTPVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.6',
      fgAvPOP3VirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.7',
      fgAvPOP3VirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.8',
      fgAvIMAPVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.9',
      fgAvIMAPVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.10',
      fgAvFTPVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.11',
      fgAvFTPVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.12',
      fgAvIMVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.13',
      fgAvIMVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.14',
      fgAvNNTPVirusDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.15',
      fgAvNNTPVirusBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.16',
      fgAvOversizedDetected => '1.3.6.1.4.1.12356.101.8.2.1.1.17',
      fgAvOversizedBlocked => '1.3.6.1.4.1.12356.101.8.2.1.1.18',
      fgAvTrapObjects => '1.3.6.1.4.1.12356.101.8.3',
      fgAvTrapObjects => '1.3.6.1.4.1.12356.101.8.3',
      fgAvTrapVirName => '1.3.6.1.4.1.12356.101.8.3.1.0',
      fgIps => '1.3.6.1.4.1.12356.101.9',
      fgIpsInfo => '1.3.6.1.4.1.12356.101.9.1',
      fgIpsTables => '1.3.6.1.4.1.12356.101.9.2',
      fgIpsTables => '1.3.6.1.4.1.12356.101.9.2',
      fgIpsStatsTable => '1.3.6.1.4.1.12356.101.9.2.1',
      fgIpsStatsEntry => '1.3.6.1.4.1.12356.101.9.2.1.1',
      fgIpsIntrusionsDetected => '1.3.6.1.4.1.12356.101.9.2.1.1.1',
      fgIpsIntrusionsBlocked => '1.3.6.1.4.1.12356.101.9.2.1.1.2',
      fgIpsCritSevDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.3',
      fgIpsHighSevDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.4',
      fgIpsMedSevDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.5',
      fgIpsLowSevDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.6',
      fgIpsInfoSevDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.7',
      fgIpsSignatureDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.8',
      fgIpsAnomalyDetections => '1.3.6.1.4.1.12356.101.9.2.1.1.9',
      fgIpsTrapObjects => '1.3.6.1.4.1.12356.101.9.3',
      fgIpsTrapObjects => '1.3.6.1.4.1.12356.101.9.3',
      fgIpsTrapSigId => '1.3.6.1.4.1.12356.101.9.3.1.0',
      fgIpsTrapSrcIp => '1.3.6.1.4.1.12356.101.9.3.2.0',
      fgIpsTrapSigMsg => '1.3.6.1.4.1.12356.101.9.3.3.0',
      fgApplications => '1.3.6.1.4.1.12356.101.10',
      fgWebfilter => '1.3.6.1.4.1.12356.101.10.1',
      fgWebfilterInfo => '1.3.6.1.4.1.12356.101.10.1.1',
      fgWebfilterTables => '1.3.6.1.4.1.12356.101.10.1.2',
      fgWebfilterTables => '1.3.6.1.4.1.12356.101.10.1.2',
      fgWebfilterStatsTable => '1.3.6.1.4.1.12356.101.10.1.2.1',
      fgWebfilterStatsEntry => '1.3.6.1.4.1.12356.101.10.1.2.1.1',
      fgWfHTTPBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.1',
      fgWfHTTPSBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.2',
      fgWfHTTPURLBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.3',
      fgWfHTTPSURLBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.4',
      fgWfActiveXBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.5',
      fgWfCookieBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.6',
      fgWfAppletBlocked => '1.3.6.1.4.1.12356.101.10.1.2.1.1.7',
      fgFortiGuardStatsTable => '1.3.6.1.4.1.12356.101.10.1.2.2',
      fgFortiGuardStatsEntry => '1.3.6.1.4.1.12356.101.10.1.2.2.1',
      fgFgWfHTTPExamined => '1.3.6.1.4.1.12356.101.10.1.2.2.1.1',
      fgFgWfHTTPSExamined => '1.3.6.1.4.1.12356.101.10.1.2.2.1.2',
      fgFgWfHTTPAllowed => '1.3.6.1.4.1.12356.101.10.1.2.2.1.3',
      fgFgWfHTTPSAllowed => '1.3.6.1.4.1.12356.101.10.1.2.2.1.4',
      fgFgWfHTTPBlocked => '1.3.6.1.4.1.12356.101.10.1.2.2.1.5',
      fgFgWfHTTPSBlocked => '1.3.6.1.4.1.12356.101.10.1.2.2.1.6',
      fgFgWfHTTPLogged => '1.3.6.1.4.1.12356.101.10.1.2.2.1.7',
      fgFgWfHTTPSLogged => '1.3.6.1.4.1.12356.101.10.1.2.2.1.8',
      fgFgWfHTTPOverridden => '1.3.6.1.4.1.12356.101.10.1.2.2.1.9',
      fgFgWfHTTPSOverridden => '1.3.6.1.4.1.12356.101.10.1.2.2.1.10',
      fgAppProxyHTTP => '1.3.6.1.4.1.12356.101.10.100',
      fgAppProxyHTTP => '1.3.6.1.4.1.12356.101.10.100',
      fgApHTTPUpTime => '1.3.6.1.4.1.12356.101.10.100.1.0',
      fgApHTTPMemUsage => '1.3.6.1.4.1.12356.101.10.100.2.0',
      fgApHTTPStatsTable => '1.3.6.1.4.1.12356.101.10.100.3',
      fgApHTTPStatsEntry => '1.3.6.1.4.1.12356.101.10.100.3.1',
      fgApHTTPReqProcessed => '1.3.6.1.4.1.12356.101.10.100.3.1.1',
      fgAppProxySMTP => '1.3.6.1.4.1.12356.101.10.101',
      fgAppProxySMTP => '1.3.6.1.4.1.12356.101.10.101',
      fgApSMTPUpTime => '1.3.6.1.4.1.12356.101.10.101.1.0',
      fgApSMTPMemUsage => '1.3.6.1.4.1.12356.101.10.101.2.0',
      fgApSMTPStatsTable => '1.3.6.1.4.1.12356.101.10.101.3',
      fgApSMTPStatsEntry => '1.3.6.1.4.1.12356.101.10.101.3.1',
      fgApSMTPReqProcessed => '1.3.6.1.4.1.12356.101.10.101.3.1.1',
      fgApSMTPSpamDetected => '1.3.6.1.4.1.12356.101.10.101.3.1.2',
      fgAppProxyPOP3 => '1.3.6.1.4.1.12356.101.10.102',
      fgAppProxyPOP3 => '1.3.6.1.4.1.12356.101.10.102',
      fgApPOP3UpTime => '1.3.6.1.4.1.12356.101.10.102.1.0',
      fgApPOP3MemUsage => '1.3.6.1.4.1.12356.101.10.102.2.0',
      fgApPOP3StatsTable => '1.3.6.1.4.1.12356.101.10.102.3',
      fgApPOP3StatsEntry => '1.3.6.1.4.1.12356.101.10.102.3.1',
      fgApPOP3ReqProcessed => '1.3.6.1.4.1.12356.101.10.102.3.1.1',
      fgApPOP3SpamDetected => '1.3.6.1.4.1.12356.101.10.102.3.1.2',
      fgAppProxyIMAP => '1.3.6.1.4.1.12356.101.10.103',
      fgAppProxyIMAP => '1.3.6.1.4.1.12356.101.10.103',
      fgApIMAPUpTime => '1.3.6.1.4.1.12356.101.10.103.1.0',
      fgApIMAPMemUsage => '1.3.6.1.4.1.12356.101.10.103.2.0',
      fgApIMAPStatsTable => '1.3.6.1.4.1.12356.101.10.103.3',
      fgApIMAPStatsEntry => '1.3.6.1.4.1.12356.101.10.103.3.1',
      fgApIMAPReqProcessed => '1.3.6.1.4.1.12356.101.10.103.3.1.1',
      fgApIMAPSpamDetected => '1.3.6.1.4.1.12356.101.10.103.3.1.2',
      fgAppProxyNNTP => '1.3.6.1.4.1.12356.101.10.104',
      fgAppProxyNNTP => '1.3.6.1.4.1.12356.101.10.104',
      fgApNNTPUpTime => '1.3.6.1.4.1.12356.101.10.104.1.0',
      fgApNNTPMemUsage => '1.3.6.1.4.1.12356.101.10.104.2.0',
      fgApNNTPStatsTable => '1.3.6.1.4.1.12356.101.10.104.3',
      fgApNNTPStatsEntry => '1.3.6.1.4.1.12356.101.10.104.3.1',
      fgApNNTPReqProcessed => '1.3.6.1.4.1.12356.101.10.104.3.1.1',
      fgAppProxyIM => '1.3.6.1.4.1.12356.101.10.105',
      fgAppProxyIM => '1.3.6.1.4.1.12356.101.10.105',
      fgApIMUpTime => '1.3.6.1.4.1.12356.101.10.105.1.0',
      fgApIMMemUsage => '1.3.6.1.4.1.12356.101.10.105.2.0',
      fgApIMStatsTable => '1.3.6.1.4.1.12356.101.10.105.3',
      fgApIMStatsEntry => '1.3.6.1.4.1.12356.101.10.105.3.1',
      fgApIMReqProcessed => '1.3.6.1.4.1.12356.101.10.105.3.1.1',
      fgAppProxySIP => '1.3.6.1.4.1.12356.101.10.106',
      fgAppProxySIP => '1.3.6.1.4.1.12356.101.10.106',
      fgApSIPUpTime => '1.3.6.1.4.1.12356.101.10.106.1.0',
      fgApSIPMemUsage => '1.3.6.1.4.1.12356.101.10.106.2.0',
      fgApSIPStatsTable => '1.3.6.1.4.1.12356.101.10.106.3',
      fgApSIPStatsEntry => '1.3.6.1.4.1.12356.101.10.106.3.1',
      fgApSIPClientReg => '1.3.6.1.4.1.12356.101.10.106.3.1.1',
      fgApSIPCallHandling => '1.3.6.1.4.1.12356.101.10.106.3.1.2',
      fgApSIPServices => '1.3.6.1.4.1.12356.101.10.106.3.1.3',
      fgApSIPOtherReq => '1.3.6.1.4.1.12356.101.10.106.3.1.4',
      fgAppScanUnit => '1.3.6.1.4.1.12356.101.10.107',
      fgAppScanUnit => '1.3.6.1.4.1.12356.101.10.107',
      fgAppSuNumber => '1.3.6.1.4.1.12356.101.10.107.1.0',
      fgAppSuStatsTable => '1.3.6.1.4.1.12356.101.10.107.2',
      fgAppSuStatsEntry => '1.3.6.1.4.1.12356.101.10.107.2.1',
      fgAppSuIndex => '1.3.6.1.4.1.12356.101.10.107.2.1.1',
      fgAppSuFileScanned => '1.3.6.1.4.1.12356.101.10.107.2.1.2',
      fgAppVoIP => '1.3.6.1.4.1.12356.101.10.108',
      fgAppVoIP => '1.3.6.1.4.1.12356.101.10.108',
      fgAppVoIPStatsTable => '1.3.6.1.4.1.12356.101.10.108.1',
      fgAppVoIPStatsEntry => '1.3.6.1.4.1.12356.101.10.108.1.1',
      fgAppVoIPConn => '1.3.6.1.4.1.12356.101.10.108.1.1.1',
      fgAppVoIPCallBlocked => '1.3.6.1.4.1.12356.101.10.108.1.1.2',
      fgAppP2P => '1.3.6.1.4.1.12356.101.10.109',
      fgAppP2P => '1.3.6.1.4.1.12356.101.10.109',
      fgAppP2PStatsTable => '1.3.6.1.4.1.12356.101.10.109.1',
      fgAppP2PStatsEntry => '1.3.6.1.4.1.12356.101.10.109.1.1',
      fgAppP2PConnBlocked => '1.3.6.1.4.1.12356.101.10.109.1.1.1',
      fgAppP2PProtoTable => '1.3.6.1.4.1.12356.101.10.109.2',
      fgAppP2PProtoEntry => '1.3.6.1.4.1.12356.101.10.109.2.1',
      fgAppP2PProtEntProto => '1.3.6.1.4.1.12356.101.10.109.2.1.1',
      fgAppP2PProtEntBytes => '1.3.6.1.4.1.12356.101.10.109.2.1.2',
      fgAppP2PProtoEntLastReset => '1.3.6.1.4.1.12356.101.10.109.2.1.3',
      fgAppIM => '1.3.6.1.4.1.12356.101.10.110',
      fgAppIM => '1.3.6.1.4.1.12356.101.10.110',
      fgAppIMStatsTable => '1.3.6.1.4.1.12356.101.10.110.1',
      fgAppIMStatsEntry => '1.3.6.1.4.1.12356.101.10.110.1.1',
      fgAppIMMessages => '1.3.6.1.4.1.12356.101.10.110.1.1.1',
      fgAppIMFileTransfered => '1.3.6.1.4.1.12356.101.10.110.1.1.2',
      fgAppIMFileTxBlocked => '1.3.6.1.4.1.12356.101.10.110.1.1.3',
      fgAppIMConnBlocked => '1.3.6.1.4.1.12356.101.10.110.1.1.4',
      fgAppProxyFTP => '1.3.6.1.4.1.12356.101.10.111',
      fgAppProxyFTP => '1.3.6.1.4.1.12356.101.10.111',
      fgApFTPUpTime => '1.3.6.1.4.1.12356.101.10.111.1.0',
      fgApFTPMemUsage => '1.3.6.1.4.1.12356.101.10.111.2.0',
      fgApFTPStatsTable => '1.3.6.1.4.1.12356.101.10.111.3',
      fgApFTPStatsEntry => '1.3.6.1.4.1.12356.101.10.111.3.1',
      fgApFTPReqProcessed => '1.3.6.1.4.1.12356.101.10.111.3.1.1',
      fgInetProto => '1.3.6.1.4.1.12356.101.11',
      fgInetProtoInfo => '1.3.6.1.4.1.12356.101.11.1',
      fgInetProtoTables => '1.3.6.1.4.1.12356.101.11.2',
      fgInetProtoTables => '1.3.6.1.4.1.12356.101.11.2',
      fgIpSessTable => '1.3.6.1.4.1.12356.101.11.2.1',
      fgIpSessEntry => '1.3.6.1.4.1.12356.101.11.2.1.1',
      fgIpSessIndex => '1.3.6.1.4.1.12356.101.11.2.1.1.1',
      fgIpSessProto => '1.3.6.1.4.1.12356.101.11.2.1.1.2',
      fgIpSessFromAddr => '1.3.6.1.4.1.12356.101.11.2.1.1.3',
      fgIpSessFromPort => '1.3.6.1.4.1.12356.101.11.2.1.1.4',
      fgIpSessToAddr => '1.3.6.1.4.1.12356.101.11.2.1.1.5',
      fgIpSessToPort => '1.3.6.1.4.1.12356.101.11.2.1.1.6',
      fgIpSessExp => '1.3.6.1.4.1.12356.101.11.2.1.1.7',
      fgIpSessVdom => '1.3.6.1.4.1.12356.101.11.2.1.1.8',
      fgIpSessStatsTable => '1.3.6.1.4.1.12356.101.11.2.2',
      fgIpSessStatsEntry => '1.3.6.1.4.1.12356.101.11.2.2.1',
      fgIpSessNumber => '1.3.6.1.4.1.12356.101.11.2.2.1.1',
      fgVpn => '1.3.6.1.4.1.12356.101.12',
      fgVpnInfo => '1.3.6.1.4.1.12356.101.12.1',
      fgVpnTables => '1.3.6.1.4.1.12356.101.12.2',
      fgVpnTables => '1.3.6.1.4.1.12356.101.12.2',
      fgVpnDialupTable => '1.3.6.1.4.1.12356.101.12.2.1',
      fgVpnDialupEntry => '1.3.6.1.4.1.12356.101.12.2.1.1',
      fgVpnDialupIndex => '1.3.6.1.4.1.12356.101.12.2.1.1.1',
      fgVpnDialupGateway => '1.3.6.1.4.1.12356.101.12.2.1.1.2',
      fgVpnDialupLifetime => '1.3.6.1.4.1.12356.101.12.2.1.1.3',
      fgVpnDialupTimeout => '1.3.6.1.4.1.12356.101.12.2.1.1.4',
      fgVpnDialupSrcBegin => '1.3.6.1.4.1.12356.101.12.2.1.1.5',
      fgVpnDialupSrcEnd => '1.3.6.1.4.1.12356.101.12.2.1.1.6',
      fgVpnDialupDstAddr => '1.3.6.1.4.1.12356.101.12.2.1.1.7',
      fgVpnDialupVdom => '1.3.6.1.4.1.12356.101.12.2.1.1.8',
      fgVpnDialupInOctets => '1.3.6.1.4.1.12356.101.12.2.1.1.9',
      fgVpnDialupOutOctets => '1.3.6.1.4.1.12356.101.12.2.1.1.10',
      fgVpnTunTable => '1.3.6.1.4.1.12356.101.12.2.2',
      fgVpnTunEntry => '1.3.6.1.4.1.12356.101.12.2.2.1',
      fgVpnTunEntIndex => '1.3.6.1.4.1.12356.101.12.2.2.1.1',
      fgVpnTunEntPhase1Name => '1.3.6.1.4.1.12356.101.12.2.2.1.2',
      fgVpnTunEntPhase2Name => '1.3.6.1.4.1.12356.101.12.2.2.1.3',
      fgVpnTunEntRemGwyIp => '1.3.6.1.4.1.12356.101.12.2.2.1.4',
      fgVpnTunEntRemGwyPort => '1.3.6.1.4.1.12356.101.12.2.2.1.5',
      fgVpnTunEntLocGwyIp => '1.3.6.1.4.1.12356.101.12.2.2.1.6',
      fgVpnTunEntLocGwyPort => '1.3.6.1.4.1.12356.101.12.2.2.1.7',
      fgVpnTunEntSelectorSrcBeginIp => '1.3.6.1.4.1.12356.101.12.2.2.1.8',
      fgVpnTunEntSelectorSrcEndIp => '1.3.6.1.4.1.12356.101.12.2.2.1.9',
      fgVpnTunEntSelectorSrcPort => '1.3.6.1.4.1.12356.101.12.2.2.1.10',
      fgVpnTunEntSelectorDstBeginIp => '1.3.6.1.4.1.12356.101.12.2.2.1.11',
      fgVpnTunEntSelectorDstEndIp => '1.3.6.1.4.1.12356.101.12.2.2.1.12',
      fgVpnTunEntSelectorDstPort => '1.3.6.1.4.1.12356.101.12.2.2.1.13',
      fgVpnTunEntSelectorProto => '1.3.6.1.4.1.12356.101.12.2.2.1.14',
      fgVpnTunEntLifeSecs => '1.3.6.1.4.1.12356.101.12.2.2.1.15',
      fgVpnTunEntLifeBytes => '1.3.6.1.4.1.12356.101.12.2.2.1.16',
      fgVpnTunEntTimeout => '1.3.6.1.4.1.12356.101.12.2.2.1.17',
      fgVpnTunEntInOctets => '1.3.6.1.4.1.12356.101.12.2.2.1.18',
      fgVpnTunEntOutOctets => '1.3.6.1.4.1.12356.101.12.2.2.1.19',
      fgVpnTunEntStatus => '1.3.6.1.4.1.12356.101.12.2.2.1.20',
      fgVpnTunEntVdom => '1.3.6.1.4.1.12356.101.12.2.2.1.21',
      fgVpnSslStatsTable => '1.3.6.1.4.1.12356.101.12.2.3',
      fgVpnSslStatsEntry => '1.3.6.1.4.1.12356.101.12.2.3.1',
      fgVpnSslState => '1.3.6.1.4.1.12356.101.12.2.3.1.1',
      fgVpnSslStatsLoginUsers => '1.3.6.1.4.1.12356.101.12.2.3.1.2',
      fgVpnSslStatsMaxUsers => '1.3.6.1.4.1.12356.101.12.2.3.1.3',
      fgVpnSslStatsActiveWebSessions => '1.3.6.1.4.1.12356.101.12.2.3.1.4',
      fgVpnSslStatsMaxWebSessions => '1.3.6.1.4.1.12356.101.12.2.3.1.5',
      fgVpnSslStatsActiveTunnels => '1.3.6.1.4.1.12356.101.12.2.3.1.6',
      fgVpnSslStatsMaxTunnels => '1.3.6.1.4.1.12356.101.12.2.3.1.7',
      fgVpnSslTunnelTable => '1.3.6.1.4.1.12356.101.12.2.4',
      fgVpnSslTunnelEntry => '1.3.6.1.4.1.12356.101.12.2.4.1',
      fgVpnSslTunnelIndex => '1.3.6.1.4.1.12356.101.12.2.4.1.1',
      fgVpnSslTunnelVdom => '1.3.6.1.4.1.12356.101.12.2.4.1.2',
      fgVpnSslTunnelUserName => '1.3.6.1.4.1.12356.101.12.2.4.1.3',
      fgVpnSslTunnelSrcIp => '1.3.6.1.4.1.12356.101.12.2.4.1.4',
      fgVpnSslTunnelIp => '1.3.6.1.4.1.12356.101.12.2.4.1.5',
      fgVpnSslTunnelUpTime => '1.3.6.1.4.1.12356.101.12.2.4.1.6',
      fgVpnSslTunnelBytesIn => '1.3.6.1.4.1.12356.101.12.2.4.1.7',
      fgVpnSslTunnelBytesOut => '1.3.6.1.4.1.12356.101.12.2.4.1.8',
      fgVpnTrapObjects => '1.3.6.1.4.1.12356.101.12.3',
      fgVpnTrapObjects => '1.3.6.1.4.1.12356.101.12.3',
      fgVpnTrapLocalGateway => '1.3.6.1.4.1.12356.101.12.3.2.0',
      fgVpnTrapRemoteGateway => '1.3.6.1.4.1.12356.101.12.3.3.0',
      fgHighAvailability => '1.3.6.1.4.1.12356.101.13',
      fgHaInfo => '1.3.6.1.4.1.12356.101.13.1',
      fgHaInfo => '1.3.6.1.4.1.12356.101.13.1',
      fgHaSystemMode => '1.3.6.1.4.1.12356.101.13.1.1.0',
      fgHaGroupId => '1.3.6.1.4.1.12356.101.13.1.2.0',
      fgHaPriority => '1.3.6.1.4.1.12356.101.13.1.3.0',
      fgHaOverride => '1.3.6.1.4.1.12356.101.13.1.4.0',
      fgHaAutoSync => '1.3.6.1.4.1.12356.101.13.1.5.0',
      fgHaSchedule => '1.3.6.1.4.1.12356.101.13.1.6.0',
      fgHaGroupName => '1.3.6.1.4.1.12356.101.13.1.7.0',
      fgHaTables => '1.3.6.1.4.1.12356.101.13.2',
      fgHaTables => '1.3.6.1.4.1.12356.101.13.2',
      fgHaStatsTable => '1.3.6.1.4.1.12356.101.13.2.1',
      fgHaStatsEntry => '1.3.6.1.4.1.12356.101.13.2.1.1',
      fgHaStatsIndex => '1.3.6.1.4.1.12356.101.13.2.1.1.1',
      fgHaStatsSerial => '1.3.6.1.4.1.12356.101.13.2.1.1.2',
      fgHaStatsCpuUsage => '1.3.6.1.4.1.12356.101.13.2.1.1.3',
      fgHaStatsMemUsage => '1.3.6.1.4.1.12356.101.13.2.1.1.4',
      fgHaStatsNetUsage => '1.3.6.1.4.1.12356.101.13.2.1.1.5',
      fgHaStatsSesCount => '1.3.6.1.4.1.12356.101.13.2.1.1.6',
      fgHaStatsPktCount => '1.3.6.1.4.1.12356.101.13.2.1.1.7',
      fgHaStatsByteCount => '1.3.6.1.4.1.12356.101.13.2.1.1.8',
      fgHaStatsIdsCount => '1.3.6.1.4.1.12356.101.13.2.1.1.9',
      fgHaStatsAvCount => '1.3.6.1.4.1.12356.101.13.2.1.1.10',
      fgHaStatsHostname => '1.3.6.1.4.1.12356.101.13.2.1.1.11',
  },
  'LARA-MIB' => {
    lantronix => '1.3.6.1.4.1.244',
    products => '1.3.6.1.4.1.244.1',
    sls => '1.3.6.1.4.1.244.1.11',
    board => '1.3.6.1.4.1.244.1.11.1',
    host => '1.3.6.1.4.1.244.1.11.2',
    Common => '1.3.6.1.4.1.244.1.11.3',
    Traps => '1.3.6.1.4.1.244.1.11.4',
    Info => '1.3.6.1.4.1.244.1.11.1.1',
    Users => '1.3.6.1.4.1.244.1.11.1.2',
    Actions => '1.3.6.1.4.1.244.1.11.1.3',
    HostInfo => '1.3.6.1.4.1.244.1.11.2.1',
    HostActions => '1.3.6.1.4.1.244.1.11.2.2',
    firmwareVersion => '1.3.6.1.4.1.244.1.11.1.1.1',
    serialNumber => '1.3.6.1.4.1.244.1.11.1.1.2',
    IP => '1.3.6.1.4.1.244.1.11.1.1.3',
    Netmask => '1.3.6.1.4.1.244.1.11.1.1.4',
    Gateway => '1.3.6.1.4.1.244.1.11.1.1.5',
    MAC => '1.3.6.1.4.1.244.1.11.1.1.6',
    HardwareRev => '1.3.6.1.4.1.244.1.11.1.1.7',
    eventType => '1.3.6.1.4.1.244.1.11.1.1.8',
    eventDesc => '1.3.6.1.4.1.244.1.11.1.1.9',
    userLoginName => '1.3.6.1.4.1.244.1.11.1.1.10',
    remoteHost => '1.3.6.1.4.1.244.1.11.1.1.11',
    checkHostPower => '1.3.6.1.4.1.244.1.11.2.1.1',
    checkHostPowerDefinition => {
      1 => 'hasPower',
      2 => 'hasnoPower',
      3 => 'error',
      4 => 'notsupported',
    },
    DummyTrap => '1.3.6.1.4.1.244.1.11.4.1',
    Loginfailed => '1.3.6.1.4.1.244.1.11.4.2',
    Loginsuccess => '1.3.6.1.4.1.244.1.11.4.3',
    SecurityViolation => '1.3.6.1.4.1.244.1.11.4.4',
    Generic => '1.3.6.1.4.1.244.1.11.4.5',
  },
  'xPAN-PRODUCTS-MIB' => {
    "x"=>1.3.6.1.4.1.25461.2.3.9
  },
  'PAN-COMMON-MIB' => {
    panCommonConfMib => '1.3.6.1.4.1.25461.2.1.1',
    panCommonObjs => '1.3.6.1.4.1.25461.2.1.2',
    panCommonEvents => '1.3.6.1.4.1.25461.2.1.3',
    panSys => '1.3.6.1.4.1.25461.2.1.2.1',
    panChassis => '1.3.6.1.4.1.25461.2.1.2.2',
    panSession => '1.3.6.1.4.1.25461.2.1.2.3',
    panMgmt => '1.3.6.1.4.1.25461.2.1.2.4',
    panGlobalProtect => '1.3.6.1.4.1.25461.2.1.2.5',
    panSys => '1.3.6.1.4.1.25461.2.1.2.1',
    panSysSwVersion => '1.3.6.1.4.1.25461.2.1.2.1.1.0',
    panSysHwVersion => '1.3.6.1.4.1.25461.2.1.2.1.2.0',
    panSysSerialNumber => '1.3.6.1.4.1.25461.2.1.2.1.3.0',
    panSysTimeZoneOffset => '1.3.6.1.4.1.25461.2.1.2.1.4.0',
    panSysDaylightSaving => '1.3.6.1.4.1.25461.2.1.2.1.5.0',
    panSysVpnClientVersion => '1.3.6.1.4.1.25461.2.1.2.1.6.0',
    panSysAppVersion => '1.3.6.1.4.1.25461.2.1.2.1.7.0',
    panSysAvVersion => '1.3.6.1.4.1.25461.2.1.2.1.8.0',
    panSysThreatVersion => '1.3.6.1.4.1.25461.2.1.2.1.9.0',
    panSysUrlFilteringVersion => '1.3.6.1.4.1.25461.2.1.2.1.10.0',
    panSysHAState => '1.3.6.1.4.1.25461.2.1.2.1.11.0',
    panSysHAPeerState => '1.3.6.1.4.1.25461.2.1.2.1.12.0',
    panSysHAMode => '1.3.6.1.4.1.25461.2.1.2.1.13.0',
    panSysUrlFilteringDatabase => '1.3.6.1.4.1.25461.2.1.2.1.14.0',
    panSysGlobalProtectClientVersion => '1.3.6.1.4.1.25461.2.1.2.1.15.0',
    panSysOpswatDatafileVersion => '1.3.6.1.4.1.25461.2.1.2.1.16.0',
    panChassis => '1.3.6.1.4.1.25461.2.1.2.2',
    panChassisType => '1.3.6.1.4.1.25461.2.1.2.2.1.0',
    panMSeriesMode => '1.3.6.1.4.1.25461.2.1.2.2.2.0',
    panSession => '1.3.6.1.4.1.25461.2.1.2.3',
    panSessionUtilization => '1.3.6.1.4.1.25461.2.1.2.3.1.0',
    panSessionMax => '1.3.6.1.4.1.25461.2.1.2.3.2.0',
    panSessionActive => '1.3.6.1.4.1.25461.2.1.2.3.3.0',
    panSessionActiveTcp => '1.3.6.1.4.1.25461.2.1.2.3.4.0',
    panSessionActiveUdp => '1.3.6.1.4.1.25461.2.1.2.3.5.0',
    panSessionActiveICMP => '1.3.6.1.4.1.25461.2.1.2.3.6.0',
    panSessionActiveSslProxy => '1.3.6.1.4.1.25461.2.1.2.3.7.0',
    panSessionSslProxyUtilization => '1.3.6.1.4.1.25461.2.1.2.3.8.0',
    panVsysTable => '1.3.6.1.4.1.25461.2.1.2.3.9',
    panVsysEntry => '1.3.6.1.4.1.25461.2.1.2.3.9.1',
    panVsysId => '1.3.6.1.4.1.25461.2.1.2.3.9.1.1',
    panVsysName => '1.3.6.1.4.1.25461.2.1.2.3.9.1.2',
    panVsysSessionUtilizationPct => '1.3.6.1.4.1.25461.2.1.2.3.9.1.3',
    panVsysActiveSessions => '1.3.6.1.4.1.25461.2.1.2.3.9.1.4',
    panVsysMaxSessions => '1.3.6.1.4.1.25461.2.1.2.3.9.1.5',
    panMgmt => '1.3.6.1.4.1.25461.2.1.2.4',
    panMgmtPanoramaConnected => '1.3.6.1.4.1.25461.2.1.2.4.1.0',
    panMgmtPanorama2Connected => '1.3.6.1.4.1.25461.2.1.2.4.2.0',
    panGPGatewayUtilization => '1.3.6.1.4.1.25461.2.1.2.5.1',
    panGPGatewayUtilization => '1.3.6.1.4.1.25461.2.1.2.5.1',
    panGPGWUtilizationPct => '1.3.6.1.4.1.25461.2.1.2.5.1.1.0',
    panGPGWUtilizationMaxTunnels => '1.3.6.1.4.1.25461.2.1.2.5.1.2.0',
    panGPGWUtilizationActiveTunnels => '1.3.6.1.4.1.25461.2.1.2.5.1.3.0',
    panCommonEventObjs => '1.3.6.1.4.1.25461.2.1.3.1',
    panCommonEventEvents => '1.3.6.1.4.1.25461.2.1.3.2',
    panCommonEventEventsV2 => '1.3.6.1.4.1.25461.2.1.3.2.0',
    panCommonEventObjs => '1.3.6.1.4.1.25461.2.1.3.1',
    panCommonEventDescr => '1.3.6.1.4.1.25461.2.1.3.1.1.0',
  },
  'OSPF-MIB' => {
    ospf => '1.3.6.1.2.1.14',
    ospfGeneralGroup => '1.3.6.1.2.1.14.1',
    ospfRouterId => '1.3.6.1.2.1.14.1.1',
    ospfAdminStat => '1.3.6.1.2.1.14.1.2',
    ospfVersionNumber => '1.3.6.1.2.1.14.1.3',
    ospfVersionNumberDefinition => 'OSPF-MIB::ospfVersionNumber',
    ospfAreaBdrRtrStatus => '1.3.6.1.2.1.14.1.4',
    ospfASBdrRtrStatus => '1.3.6.1.2.1.14.1.5',
    ospfExternLsaCount => '1.3.6.1.2.1.14.1.6',
    ospfExternLsaCksumSum => '1.3.6.1.2.1.14.1.7',
    ospfTOSSupport => '1.3.6.1.2.1.14.1.8',
    ospfOriginateNewLsas => '1.3.6.1.2.1.14.1.9',
    ospfRxNewLsas => '1.3.6.1.2.1.14.1.10',
    ospfExtLsdbLimit => '1.3.6.1.2.1.14.1.11',
    ospfMulticastExtensions => '1.3.6.1.2.1.14.1.12',
    ospfExitOverflowInterval => '1.3.6.1.2.1.14.1.13',
    ospfDemandExtensions => '1.3.6.1.2.1.14.1.14',
    ospfRFC1583Compatibility => '1.3.6.1.2.1.14.1.15',
    ospfOpaqueLsaSupport => '1.3.6.1.2.1.14.1.16',
    ospfReferenceBandwidth => '1.3.6.1.2.1.14.1.17',
    ospfRestartSupport => '1.3.6.1.2.1.14.1.18',
    ospfRestartSupportDefinition => 'OSPF-MIB::ospfRestartSupport',
    ospfRestartInterval => '1.3.6.1.2.1.14.1.19',
    ospfRestartStrictLsaChecking => '1.3.6.1.2.1.14.1.20',
    ospfRestartStatus => '1.3.6.1.2.1.14.1.21',
    ospfRestartStatusDefinition => 'OSPF-MIB::ospfRestartStatus',
    ospfRestartAge => '1.3.6.1.2.1.14.1.22',
    ospfRestartExitReason => '1.3.6.1.2.1.14.1.23',
    ospfRestartExitReasonDefinition => 'OSPF-MIB::ospfRestartExitReason',
    ospfAsLsaCount => '1.3.6.1.2.1.14.1.24',
    ospfAsLsaCksumSum => '1.3.6.1.2.1.14.1.25',
    ospfStubRouterSupport => '1.3.6.1.2.1.14.1.26',
    ospfStubRouterAdvertisement => '1.3.6.1.2.1.14.1.27',
    ospfStubRouterAdvertisementDefinition => 'OSPF-MIB::ospfStubRouterAdvertisement',
    ospfDiscontinuityTime => '1.3.6.1.2.1.14.1.28',
    ospfAreaTable => '1.3.6.1.2.1.14.2',
    ospfAreaEntry => '1.3.6.1.2.1.14.2.1',
    ospfAreaId => '1.3.6.1.2.1.14.2.1.1',
    ospfAuthType => '1.3.6.1.2.1.14.2.1.2',
    ospfAuthTypeDefinition => {
      0 => 'none',
      1 => 'simplePassword',
      2 => 'md5',
    },
    ospfImportAsExtern => '1.3.6.1.2.1.14.2.1.3',
    ospfImportAsExternDefinition => 'OSPF-MIB::ospfImportAsExtern',
    ospfSpfRuns => '1.3.6.1.2.1.14.2.1.4',
    ospfAreaBdrRtrCount => '1.3.6.1.2.1.14.2.1.5',
    ospfAsBdrRtrCount => '1.3.6.1.2.1.14.2.1.6',
    ospfAreaLsaCount => '1.3.6.1.2.1.14.2.1.7',
    ospfAreaLsaCksumSum => '1.3.6.1.2.1.14.2.1.8',
    ospfAreaSummary => '1.3.6.1.2.1.14.2.1.9',
    ospfAreaSummaryDefinition => 'OSPF-MIB::ospfAreaSummary',
    ospfAreaStatus => '1.3.6.1.2.1.14.2.1.10',
    ospfAreaStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ospfAreaNssaTranslatorRole => '1.3.6.1.2.1.14.2.1.11',
    ospfAreaNssaTranslatorRoleDefinition => 'OSPF-MIB::ospfAreaNssaTranslatorRole',
    ospfAreaNssaTranslatorState => '1.3.6.1.2.1.14.2.1.12',
    ospfAreaNssaTranslatorStateDefinition => 'OSPF-MIB::ospfAreaNssaTranslatorState',
    ospfAreaNssaTranslatorStabilityInterval => '1.3.6.1.2.1.14.2.1.13',
    ospfAreaNssaTranslatorEvents => '1.3.6.1.2.1.14.2.1.14',
    ospfStubAreaTable => '1.3.6.1.2.1.14.3',
    ospfStubAreaEntry => '1.3.6.1.2.1.14.3.1',
    ospfStubAreaId => '1.3.6.1.2.1.14.3.1.1',
    ospfStubTOS => '1.3.6.1.2.1.14.3.1.2',
    ospfStubMetric => '1.3.6.1.2.1.14.3.1.3',
    ospfStubStatus => '1.3.6.1.2.1.14.3.1.4',
    ospfStubMetricType => '1.3.6.1.2.1.14.3.1.5',
    ospfStubMetricTypeDefinition => 'OSPF-MIB::ospfStubMetricType',
    ospfLsdbTable => '1.3.6.1.2.1.14.4',
    ospfLsdbEntry => '1.3.6.1.2.1.14.4.1',
    ospfLsdbAreaId => '1.3.6.1.2.1.14.4.1.1',
    ospfLsdbType => '1.3.6.1.2.1.14.4.1.2',
    ospfLsdbTypeDefinition => 'OSPF-MIB::ospfLsdbType',
    ospfLsdbLsid => '1.3.6.1.2.1.14.4.1.3',
    ospfLsdbRouterId => '1.3.6.1.2.1.14.4.1.4',
    ospfLsdbSequence => '1.3.6.1.2.1.14.4.1.5',
    ospfLsdbAge => '1.3.6.1.2.1.14.4.1.6',
    ospfLsdbChecksum => '1.3.6.1.2.1.14.4.1.7',
    ospfLsdbAdvertisement => '1.3.6.1.2.1.14.4.1.8',
    ospfAreaRangeTable => '1.3.6.1.2.1.14.5',
    ospfAreaRangeEntry => '1.3.6.1.2.1.14.5.1',
    ospfAreaRangeAreaId => '1.3.6.1.2.1.14.5.1.1',
    ospfAreaRangeNet => '1.3.6.1.2.1.14.5.1.2',
    ospfAreaRangeMask => '1.3.6.1.2.1.14.5.1.3',
    ospfAreaRangeStatus => '1.3.6.1.2.1.14.5.1.4',
    ospfAreaRangeEffect => '1.3.6.1.2.1.14.5.1.5',
    ospfAreaRangeEffectDefinition => 'OSPF-MIB::ospfAreaRangeEffect',
    ospfHostTable => '1.3.6.1.2.1.14.6',
    ospfHostEntry => '1.3.6.1.2.1.14.6.1',
    ospfHostIpAddress => '1.3.6.1.2.1.14.6.1.1',
    ospfHostTOS => '1.3.6.1.2.1.14.6.1.2',
    ospfHostMetric => '1.3.6.1.2.1.14.6.1.3',
    ospfHostStatus => '1.3.6.1.2.1.14.6.1.4',
    ospfHostStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ospfHostAreaID => '1.3.6.1.2.1.14.6.1.5',
    ospfHostCfgAreaID => '1.3.6.1.2.1.14.6.1.6',
    ospfIfTable => '1.3.6.1.2.1.14.7',
    ospfIfEntry => '1.3.6.1.2.1.14.7.1',
    ospfIfIpAddress => '1.3.6.1.2.1.14.7.1.1',
    ospfAddressLessIf => '1.3.6.1.2.1.14.7.1.2',
    ospfIfAreaId => '1.3.6.1.2.1.14.7.1.3',
    ospfIfType => '1.3.6.1.2.1.14.7.1.4',
    ospfIfTypeDefinition => 'OSPF-MIB::ospfIfType',
    ospfIfAdminStat => '1.3.6.1.2.1.14.7.1.5',
    ospfIfAdminStatDefinition => 'OSPF-MIB::Status',
    ospfIfRtrPriority => '1.3.6.1.2.1.14.7.1.6',
    ospfIfTransitDelay => '1.3.6.1.2.1.14.7.1.7',
    ospfIfRetransInterval => '1.3.6.1.2.1.14.7.1.8',
    ospfIfHelloInterval => '1.3.6.1.2.1.14.7.1.9',
    ospfIfRtrDeadInterval => '1.3.6.1.2.1.14.7.1.10',
    ospfIfPollInterval => '1.3.6.1.2.1.14.7.1.11',
    ospfIfState => '1.3.6.1.2.1.14.7.1.12',
    ospfIfStateDefinition => 'OSPF-MIB::ospfIfState',
    ospfIfDesignatedRouter => '1.3.6.1.2.1.14.7.1.13',
    ospfIfBackupDesignatedRouter => '1.3.6.1.2.1.14.7.1.14',
    ospfIfEvents => '1.3.6.1.2.1.14.7.1.15',
    ospfIfAuthKey => '1.3.6.1.2.1.14.7.1.16',
    ospfIfStatus => '1.3.6.1.2.1.14.7.1.17',
    ospfIfStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ospfIfMulticastForwarding => '1.3.6.1.2.1.14.7.1.18',
    ospfIfMulticastForwardingDefinition => 'OSPF-MIB::ospfIfMulticastForwarding',
    ospfIfDemand => '1.3.6.1.2.1.14.7.1.19',
    ospfIfDemandDefinition => 'SNMPv2-TC-v1::TruthValue',
    ospfIfAuthType => '1.3.6.1.2.1.14.7.1.20',
    ospfIfAuthTypeDefinition => 'OSPF-MIB::AuType',
    ospfIfLsaCount => '1.3.6.1.2.1.14.7.1.21',
    ospfIfLsaCksumSum => '1.3.6.1.2.1.14.7.1.22',
    ospfIfDesignatedRouterId => '1.3.6.1.2.1.14.7.1.23',
    ospfIfBackupDesignatedRouterId => '1.3.6.1.2.1.14.7.1.24',
    ospfIfMetricTable => '1.3.6.1.2.1.14.8',
    ospfIfMetricEntry => '1.3.6.1.2.1.14.8.1',
    ospfIfMetricIpAddress => '1.3.6.1.2.1.14.8.1.1',
    ospfIfMetricAddressLessIf => '1.3.6.1.2.1.14.8.1.2',
    ospfIfMetricTOS => '1.3.6.1.2.1.14.8.1.3',
    ospfIfMetricValue => '1.3.6.1.2.1.14.8.1.4',
    ospfIfMetricStatus => '1.3.6.1.2.1.14.8.1.5',
    ospfIfMetricStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ospfVirtIfTable => '1.3.6.1.2.1.14.9',
    ospfVirtIfEntry => '1.3.6.1.2.1.14.9.1',
    ospfVirtIfAreaId => '1.3.6.1.2.1.14.9.1.1',
    ospfVirtIfNeighbor => '1.3.6.1.2.1.14.9.1.2',
    ospfVirtIfTransitDelay => '1.3.6.1.2.1.14.9.1.3',
    ospfVirtIfRetransInterval => '1.3.6.1.2.1.14.9.1.4',
    ospfVirtIfHelloInterval => '1.3.6.1.2.1.14.9.1.5',
    ospfVirtIfRtrDeadInterval => '1.3.6.1.2.1.14.9.1.6',
    ospfVirtIfState => '1.3.6.1.2.1.14.9.1.7',
    ospfVirtIfStateDefinition => 'OSPF-MIB::ospfVirtIfState',
    ospfVirtIfEvents => '1.3.6.1.2.1.14.9.1.8',
    ospfVirtIfAuthKey => '1.3.6.1.2.1.14.9.1.9',
    ospfVirtIfStatus => '1.3.6.1.2.1.14.9.1.10',
    ospfVirtIfAuthType => '1.3.6.1.2.1.14.9.1.11',
    ospfVirtIfLsaCount => '1.3.6.1.2.1.14.9.1.12',
    ospfVirtIfLsaCksumSum => '1.3.6.1.2.1.14.9.1.13',
    ospfNbrTable => '1.3.6.1.2.1.14.10',
    ospfNbrEntry => '1.3.6.1.2.1.14.10.1',
    ospfNbrIpAddr => '1.3.6.1.2.1.14.10.1.1',
    ospfNbrAddressLessIndex => '1.3.6.1.2.1.14.10.1.2',
    ospfNbrRtrId => '1.3.6.1.2.1.14.10.1.3',
    ospfNbrOptions => '1.3.6.1.2.1.14.10.1.4',
    ospfNbrPriority => '1.3.6.1.2.1.14.10.1.5',
    ospfNbrState => '1.3.6.1.2.1.14.10.1.6',
    ospfNbrStateDefinition => 'OSPF-MIB::ospfNbrState',
    ospfNbrEvents => '1.3.6.1.2.1.14.10.1.7',
    ospfNbrLsRetransQLen => '1.3.6.1.2.1.14.10.1.8',
    ospfNbmaNbrStatus => '1.3.6.1.2.1.14.10.1.9',
    ospfNbmaNbrStatusDefinition => 'SNMPv2-TC-v1::RowStatus',
    ospfNbmaNbrPermanence => '1.3.6.1.2.1.14.10.1.10',
    ospfNbmaNbrPermanenceDefinition => 'OSPF-MIB::ospfNbmaNbrPermanence',
    ospfNbrHelloSuppressed => '1.3.6.1.2.1.14.10.1.11',
    ospfNbrHelloSuppressedDefinition => 'SNMPv2-TC-v1::TruthValue',
    ospfNbrRestartHelperStatus => '1.3.6.1.2.1.14.10.1.12',
    ospfNbrRestartHelperStatusDefinition => 'OSPF-MIB::ospfNbrRestartHelperStatus',
    ospfNbrRestartHelperAge => '1.3.6.1.2.1.14.10.1.13',
    ospfNbrRestartHelperExitReason => '1.3.6.1.2.1.14.10.1.14',
    ospfNbrRestartHelperExitReasonDefinition => 'OSPF-MIB::ospfNbrRestartHelperExitReason',
    ospfVirtNbrTable => '1.3.6.1.2.1.14.11',
    ospfVirtNbrEntry => '1.3.6.1.2.1.14.11.1',
    ospfVirtNbrArea => '1.3.6.1.2.1.14.11.1.1',
    ospfVirtNbrRtrId => '1.3.6.1.2.1.14.11.1.2',
    ospfVirtNbrIpAddr => '1.3.6.1.2.1.14.11.1.3',
    ospfVirtNbrOptions => '1.3.6.1.2.1.14.11.1.4',
    ospfVirtNbrOptionsDefinition => 'OSPF-MIB::ospfVirtNbrOptions',
    ospfVirtNbrState => '1.3.6.1.2.1.14.11.1.5',
    ospfVirtNbrStateDefinition => 'OSPF-MIB::ospfVirtNbrState',
    ospfVirtNbrEvents => '1.3.6.1.2.1.14.11.1.6',
    ospfVirtNbrLsRetransQLen => '1.3.6.1.2.1.14.11.1.7',
    ospfVirtNbrHelloSuppressed => '1.3.6.1.2.1.14.11.1.8',
    ospfVirtNbrRestartHelperStatus => '1.3.6.1.2.1.14.11.1.9',
    ospfVirtNbrRestartHelperStatusDefinition => 'OSPF-MIB::ospfVirtNbrRestartHelperStatus',
    ospfVirtNbrRestartHelperAge => '1.3.6.1.2.1.14.11.1.10',
    ospfVirtNbrRestartHelperExitReason => '1.3.6.1.2.1.14.11.1.11',
    ospfVirtNbrRestartHelperExitReasonDefinition => 'OSPF-MIB::ospfVirtNbrRestartHelperExitReason',
    ospfExtLsdbTable => '1.3.6.1.2.1.14.12',
    ospfExtLsdbEntry => '1.3.6.1.2.1.14.12.1',
    ospfExtLsdbType => '1.3.6.1.2.1.14.12.1.1',
    ospfExtLsdbTypeDefinition => 'OSPF-MIB::ospfExtLsdbType',
    ospfExtLsdbLsid => '1.3.6.1.2.1.14.12.1.2',
    ospfExtLsdbRouterId => '1.3.6.1.2.1.14.12.1.3',
    ospfExtLsdbSequence => '1.3.6.1.2.1.14.12.1.4',
    ospfExtLsdbAge => '1.3.6.1.2.1.14.12.1.5',
    ospfExtLsdbChecksum => '1.3.6.1.2.1.14.12.1.6',
    ospfExtLsdbAdvertisement => '1.3.6.1.2.1.14.12.1.7',
    ospfRouteGroup => '1.3.6.1.2.1.14.13',
    ospfIntraArea => '1.3.6.1.2.1.14.13.1',
    ospfInterArea => '1.3.6.1.2.1.14.13.2',
    ospfExternalType1 => '1.3.6.1.2.1.14.13.3',
    ospfExternalType2 => '1.3.6.1.2.1.14.13.4',
    ospfAreaAggregateTable => '1.3.6.1.2.1.14.14',
    ospfAreaAggregateEntry => '1.3.6.1.2.1.14.14.1',
    ospfAreaAggregateAreaID => '1.3.6.1.2.1.14.14.1.1',
    ospfAreaAggregateLsdbType => '1.3.6.1.2.1.14.14.1.2',
    ospfAreaAggregateLsdbTypeDefinition => 'OSPF-MIB::ospfAreaAggregateLsdbType',
    ospfAreaAggregateNet => '1.3.6.1.2.1.14.14.1.3',
    ospfAreaAggregateMask => '1.3.6.1.2.1.14.14.1.4',
    ospfAreaAggregateStatus => '1.3.6.1.2.1.14.14.1.5',
    ospfAreaAggregateEffect => '1.3.6.1.2.1.14.14.1.6',
    ospfAreaAggregateEffectDefinition => 'OSPF-MIB::ospfAreaAggregateEffect',
    ospfAreaAggregateExtRouteTag => '1.3.6.1.2.1.14.14.1.7',
    ospfConformance => '1.3.6.1.2.1.14.15',
    ospfGroups => '1.3.6.1.2.1.14.15.1',
    ospfCompliances => '1.3.6.1.2.1.14.15.2',
    ospfLocalLsdbTable => '1.3.6.1.2.1.14.17',
    ospfLocalLsdbEntry => '1.3.6.1.2.1.14.17.1',
    ospfLocalLsdbIpAddress => '1.3.6.1.2.1.14.17.1.1',
    ospfLocalLsdbAddressLessIf => '1.3.6.1.2.1.14.17.1.2',
    ospfLocalLsdbType => '1.3.6.1.2.1.14.17.1.3',
    ospfLocalLsdbTypeDefinition => 'OSPF-MIB::ospfLocalLsdbType',
    ospfLocalLsdbLsid => '1.3.6.1.2.1.14.17.1.4',
    ospfLocalLsdbRouterId => '1.3.6.1.2.1.14.17.1.5',
    ospfLocalLsdbSequence => '1.3.6.1.2.1.14.17.1.6',
    ospfLocalLsdbAge => '1.3.6.1.2.1.14.17.1.7',
    ospfLocalLsdbChecksum => '1.3.6.1.2.1.14.17.1.8',
    ospfLocalLsdbAdvertisement => '1.3.6.1.2.1.14.17.1.9',
    ospfVirtLocalLsdbTable => '1.3.6.1.2.1.14.18',
    ospfVirtLocalLsdbEntry => '1.3.6.1.2.1.14.18.1',
    ospfVirtLocalLsdbTransitArea => '1.3.6.1.2.1.14.18.1.1',
    ospfVirtLocalLsdbNeighbor => '1.3.6.1.2.1.14.18.1.2',
    ospfVirtLocalLsdbType => '1.3.6.1.2.1.14.18.1.3',
    ospfVirtLocalLsdbTypeDefinition => 'OSPF-MIB::ospfVirtLocalLsdbType',
    ospfVirtLocalLsdbLsid => '1.3.6.1.2.1.14.18.1.4',
    ospfVirtLocalLsdbRouterId => '1.3.6.1.2.1.14.18.1.5',
    ospfVirtLocalLsdbSequence => '1.3.6.1.2.1.14.18.1.6',
    ospfVirtLocalLsdbAge => '1.3.6.1.2.1.14.18.1.7',
    ospfVirtLocalLsdbChecksum => '1.3.6.1.2.1.14.18.1.8',
    ospfVirtLocalLsdbAdvertisement => '1.3.6.1.2.1.14.18.1.9',
    ospfAsLsdbTable => '1.3.6.1.2.1.14.19',
    ospfAsLsdbEntry => '1.3.6.1.2.1.14.19.1',
    ospfAsLsdbType => '1.3.6.1.2.1.14.19.1.1',
    ospfAsLsdbTypeDefinition => 'OSPF-MIB::ospfAsLsdbType',
    ospfAsLsdbLsid => '1.3.6.1.2.1.14.19.1.2',
    ospfAsLsdbRouterId => '1.3.6.1.2.1.14.19.1.3',
    ospfAsLsdbSequence => '1.3.6.1.2.1.14.19.1.4',
    ospfAsLsdbAge => '1.3.6.1.2.1.14.19.1.5',
    ospfAsLsdbChecksum => '1.3.6.1.2.1.14.19.1.6',
    ospfAsLsdbAdvertisement => '1.3.6.1.2.1.14.19.1.7',
    ospfAreaLsaCountTable => '1.3.6.1.2.1.14.20',
    ospfAreaLsaCountEntry => '1.3.6.1.2.1.14.20.1',
    ospfAreaLsaCountAreaId => '1.3.6.1.2.1.14.20.1.1',
    ospfAreaLsaCountLsaType => '1.3.6.1.2.1.14.20.1.2',
    ospfAreaLsaCountLsaTypeDefinition => 'OSPF-MIB::ospfAreaLsaCountLsaType',
    ospfAreaLsaCountNumber => '1.3.6.1.2.1.14.20.1.3',
  },
  'S5-CHASSIS-MIB' => {
    s5ChasUtil => '1.3.6.1.4.1.45.1.6.3.8',
    s5ChasUtilTable => '1.3.6.1.4.1.45.1.6.3.8.1',
    s5ChasUtilEntry => '1.3.6.1.4.1.45.1.6.3.8.1.1',
    s5ChasUtilGrpIndx => '1.3.6.1.4.1.45.1.6.3.8.1.1.1',
    s5ChasUtilIndx => '1.3.6.1.4.1.45.1.6.3.8.1.1.2',
    s5ChasUtilSubIndx => '1.3.6.1.4.1.45.1.6.3.8.1.1.3',
    s5ChasUtilTotalCPUUsage => '1.3.6.1.4.1.45.1.6.3.8.1.1.4',
    s5ChasUtilCPUUsageLast1Minute => '1.3.6.1.4.1.45.1.6.3.8.1.1.5',
    s5ChasUtilCPUUsageLast10Minutes => '1.3.6.1.4.1.45.1.6.3.8.1.1.6',
    s5ChasUtilCPUUsageLast1Hour => '1.3.6.1.4.1.45.1.6.3.8.1.1.7',
    s5ChasUtilCPUUsageLast24Hours => '1.3.6.1.4.1.45.1.6.3.8.1.1.8',
    s5ChasUtilMemoryAvailable => '1.3.6.1.4.1.45.1.6.3.8.1.1.9',
    s5ChasUtilMemoryMinAvailable => '1.3.6.1.4.1.45.1.6.3.8.1.1.10',
    s5ChasUtilCPUUsageLast10Seconds => '1.3.6.1.4.1.45.1.6.3.8.1.1.11',
  },
  'RAPID-CITY-MIB' => {
    rcSysCpuUtil => '1.3.6.1.4.1.2272.1.1.20',
    rcSysDramSize => '1.3.6.1.4.1.2272.1.1.46',
    rcSysDramUsed => '1.3.6.1.4.1.2272.1.1.47',
    rcSysDramFree => '1.3.6.1.4.1.2272.1.1.48',
    rcChasSerialNumber => '1.3.6.1.4.1.2272.1.4.2',
    rcChasHardwareRevision => '1.3.6.1.4.1.2272.1.4.3',
    rcChasNumSlots => '1.3.6.1.4.1.2272.1.4.4',
    rcChasNumPorts => '1.3.6.1.4.1.2272.1.4.5',
    rcChasTestResult => '1.3.6.1.4.1.2272.1.4.6',
    rcChasTestResultDefinition => {
      3 => 'crceeprom',
      6 => 'led',
      7 => 'formaccpuaccess',
      8 => 'asiccpuaccess',
      4 => 'timer',
      2 => 'ok',
      9 => 'memory',
      5 => 'procdram',
      1 => 'other',
      10 => 'loopback',
    },
    rcChasFan => '1.3.6.1.4.1.2272.1.4.7',
    rcChasFanTable => '1.3.6.1.4.1.2272.1.4.7.1',
    rcChasFanEntry => '1.3.6.1.4.1.2272.1.4.7.1.1',
    rcChasFanId => '1.3.6.1.4.1.2272.1.4.7.1.1.1',
    rcChasFanOperStatus => '1.3.6.1.4.1.2272.1.4.7.1.1.2',
    rcChasFanOperStatusDefinition => {
      1 => 'unknown',
      3 => 'down',
      2 => 'up',
    },
    rcChasFanAmbientTemperature => '1.3.6.1.4.1.2272.1.4.7.1.1.3',
    rcChasPowerSupply => '1.3.6.1.4.1.2272.1.4.8',
    rcChasPowerSupplyTable => '1.3.6.1.4.1.2272.1.4.8.1',
    rcChasPowerSupplyEntry => '1.3.6.1.4.1.2272.1.4.8.1.1',
    rcChasPowerSupplyId => '1.3.6.1.4.1.2272.1.4.8.1.1.1',
    rcChasPowerSupplyOperStatus => '1.3.6.1.4.1.2272.1.4.8.1.1.2',
    rcChasPowerSupplyOperStatusDefinition => {
      1 => 'unknown',
      4 => 'down',
      3 => 'up',
      2 => 'empty',
    },
    rcChasPowerSupplyDetailTable => '1.3.6.1.4.1.2272.1.4.8.2',
    rcChasPowerSupplyDetailEntry => '1.3.6.1.4.1.2272.1.4.8.2.1',
    rcChasPowerSupplyDetailId => '1.3.6.1.4.1.2272.1.4.8.2.1.1',
    rcChasPowerSupplyDetailType => '1.3.6.1.4.1.2272.1.4.8.2.1.2',
    rcChasPowerSupplyDetailTypeDefinition => {
      2 => 'dc',
      0 => 'unknown',
      1 => 'ac',
    },
    rcChasPowerSupplyDetailSerialNumber => '1.3.6.1.4.1.2272.1.4.8.2.1.3',
    rcChasPowerSupplyDetailHardwareRevision => '1.3.6.1.4.1.2272.1.4.8.2.1.4',
    rcChasPowerSupplyDetailPartNumber => '1.3.6.1.4.1.2272.1.4.8.2.1.5',
    rcChasPowerSupplyDetailDescription => '1.3.6.1.4.1.2272.1.4.8.2.1.6',
  },
};

$Monitoring::GLPlugin::SNMP::definitions = {
  'CISCO-ENVMON-MIB' => {
     ciscoEnvMonState => {
       1 => 'normal',
       2 => 'warning',
       3 => 'critical',
       4 => 'shutdown',
       5 => 'notPresent',
       6 => 'notFunctioning',
     },
  },
  'CISCO-HSRP-MIB' => {
      HsrpState => {
        1 => 'initial',
        2 => 'learn',
        3 => 'listen',
        4 => 'speak',
        5 => 'standby',
        6 => 'active',
      },
  },
  'SNMPv2-TC-v1' => {
      'TruthValue' => {
        1 => 'true',
        2 => 'false',
      },
      'RowStatus' => {
        1 => 'active',
        2 => 'notInService',
        3 => 'notReady',
        4 => 'createAndGo',
        5 => 'createAndWait',
        6 => 'destroy',
      },
  },
  'CISCO-ENTITY-SENSOR-MIB' => {
      'SensorDataType' => {
        1 => 'other',
        2 => 'unknown',
        3 => 'voltsAC',
        4 => 'voltsDC',
        5 => 'amperes',
        6 => 'watts',
        7 => 'hertz',
        8 => 'celsius',
        9 => 'percentRH',
        10 => 'rpm',
        11 => 'cmm',
        12 => 'truthvalue',
        13 => 'specialEnum',
        14 => 'dBm',
      },
      'SensorStatus' => {
        1 => 'ok',
        2 => 'unavailable',
        3 => 'nonoperational',
      },
      'SensorDataScale' => {
        1 => 'yocto',
        2 => 'zepto',
        3 => 'atto',
        4 => 'femto',
        5 => 'pico',
        6 => 'nano',
        7 => 'micro',
        8 => 'milli',
        9 => 'units',
        10 => 'kilo',
        11 => 'mega',
        12 => 'giga',
        13 => 'tera',
        14 => 'exa',
        15 => 'peta',
        16 => 'zetta',
        17 => 'yotta',
      },
      'SensorThresholdSeverity' => {
        1 => 'other',
        10 => 'minor',
        20 => 'major',
        30 => 'critical',
      },
      'SensorThresholdRelation' => {
        1 => 'lessThan',
        2 => 'lessOrEqual',
        3 => 'greaterThan',
        4 => 'greaterOrEqual',
        5 => 'equalTo',
        6 => 'notEqualTo',
      },
  },
  'CISCO-ENTITY-FRU-CONTROL-MIB' => {
    'PowerRedundancyType' => {
      1 => 'notsupported',
      2 => 'redundant',
      3 => 'combined',
      4 => 'nonRedundant',
      5 => 'psRedundant',
      6 => 'inPwrSrcRedundant',
      7 => 'psRedundantSingleInput',
    },
    'PowerAdminType' => {
      1 => 'on',
      2 => 'off',
      3 => 'inlineAuto',
      4 => 'inlineOn',
      5 => 'powerCycle',
    },
    'PowerOperType' => {
      1 => 'offEnvOther',
      2 => 'on',
      3 => 'offAdmin',
      4 => 'offDenied',
      5 => 'offEnvPower',
      6 => 'offEnvTemp',
      7 => 'offEnvFan',
      8 => 'failed',
      9 => 'onButFanFail',
      10 => 'offCooling',
      11 => 'offConnectorRating',
      12 => 'onButInlinePowerFail',
    },
  },
  'CISCO-L2L3-INTERFACE-CONFIG-MIB' => {
      'CL2L3InterfaceMode' => {
        1 => 'routed',
        2 => 'switchport',
      },
  },
  'CISCO-FIREWALL-MIB' => {
    'Services' => {
      1 => 'otherFWService',
      2 => 'fileXferFtp',
      3 => 'fileXferTftp',
      4 => 'fileXferFtps',
      5 => 'loginTelnet',
      6 => 'loginRlogin',
      7 => 'loginTelnets',
      8 => 'remoteExecSunRPC',
      9 => 'remoteExecMSRPC',
      10 => 'remoteExecRsh',
      11 => 'remoteExecXserver',
      12 => 'webHttp',
      13 => 'webHttps',
      14 => 'mailSmtp',
      15 => 'multimediaStreamworks',
      16 => 'multimediaH323',
      17 => 'multimediaNetShow',
      18 => 'multimediaVDOLive',
      19 => 'multimediaRealAV',
      20 => 'multimediaRTSP',
      21 => 'dbOracle',
      22 => 'dbMSsql',
      23 => 'contInspProgLang',
      24 => 'contInspUrl',
      25 => 'directoryNis',
      26 => 'directoryDns',
      27 => 'directoryNetbiosns',
      28 => 'directoryNetbiosdgm',
      29 => 'directoryNetbiosssn',
      30 => 'directoryWins',
      31 => 'qryWhois',
      32 => 'qryFinger',
      33 => 'qryIdent',
      34 => 'fsNfsStatus',
      35 => 'fsNfs',
      36 => 'fsCifs',
      37 => 'protoIcmp',
      38 => 'protoTcp',
      39 => 'protoUdp',
      40 => 'protoIp',
      41 => 'protoSnmp',
    },
  },
  'F5-BIGIP-LOCAL-MIB' => {
    ltmPoolLbMode => {
      0 => 'roundRobin',
      1 => 'ratioMember',
      2 => 'leastConnMember',
      3 => 'observedMember',
      4 => 'predictiveMember',
      5 => 'ratioNodeAddress',
      6 => 'leastConnNodeAddress',
      7 => 'fastestNodeAddress',
      8 => 'observedNodeAddress',
      9 => 'predictiveNodeAddress',
      10 => 'dynamicRatio',
      11 => 'fastestAppResponse',
      12 => 'leastSessions',
      13 => 'dynamicRatioMember',
      14 => 'l3Addr',
      15 => 'weightedLeastConnMember',
      16 => 'weightedLeastConnNodeAddr',
      17 => 'ratioSession',
    },
    ltmPoolAvailabilityState => {
      0 => 'none',
      1 => 'green',
      2 => 'yellow',
      3 => 'red',
      4 => 'blue',
    },
    ltmPoolMemberMonitorState => {
      0 => 'unchecked',
      1 => 'checking',
      2 => 'inband',
      3 => 'forced-up',
      4 => 'up',
      19 => 'down',
      20 => 'forced-down',
      22 => 'irule-down',
      23 => 'inband-down',
      24 => 'down-manual-resume',
      25 => 'disabled',
    },
    ltmPoolMemberMonitorStatus => {
      0 => 'unchecked',
      1 => 'checking',
      2 => 'inband',
      3 => 'forced-up',
      4 => 'up',
      18 => 'addr-down',
      19 => 'down',
      20 => 'forced-down',
      21 => 'maint',
      22 => 'irule-down',
      23 => 'inband-down',
      24 => 'down-manual-resume',
    },
    ltmPoolMemberEnabledState => {
      0 => 'none',
      1 => 'enabled',
      2 => 'disabled',
      3 => 'disabledbyparent',
    },
    ltmPoolStatusAvailState => {
      0 => 'none',
      1 => 'green',
      2 => 'yellow',
      3 => 'red',
      4 => 'blue',
      5 => 'grey',
    },
    ltmPoolStatusEnabledState =>  {
      0 => 'none',
      1 => 'enabled',
      2 => 'disabled',
      3 => 'disabledbyparent',
    },
    ltmPoolMbrStatusAvailState => {
      0 => 'none',
      1 => 'green',
      2 => 'yellow',
      3 => 'red',
      4 => 'blue',
      5 => 'gray',
    },
    ltmPoolMbrStatusEnabledState => {
      0 => 'none',
      1 => 'enabled',
      2 => 'disabled',
      3 => 'disabledbyparent',
    },
    ltmPoolMemberMonitorState => {
      0 => 'unchecked',
      1 => 'checking',
      2 => 'inband',
      3 => 'forced-up',
      4 => 'up',
      19 => 'down',
      20 => 'forced-down',
      22 => 'irule-down',
      23 => 'inband-down',
      24 => 'down-manual-resume',
      25 => 'disabled',
    },
    ltmPoolMemberMonitorStatus => {
      0 => 'unchecked',
      1 => 'checking',
      2 => 'inband',
      3 => 'forced-up',
      4 => 'up',
      18 => 'addr-down',
      19 => 'down',
      20 => 'forced-down',
      21 => 'maint',
      22 => 'irule-down',
      23 => 'inband-down',
      24 => 'down-manual-resume',
    },
  },
  'FOUNDRY-SN-SW-L4-SWITCH-GROUP-MIB' => {
    'L4Status' => {
      0 => 'disabled',
      1 => 'enabled',
    },
    'L4DeleteState' => {
      0 => 'done',
      1 => 'waitunbind',
      1 => 'waitdelete',
    },
    'L4RowSts' => {
      1 => 'other',
      2 => 'valid',
      3 => 'delete',
      4 => 'create',
      5 => 'modify',
    },
  },
  'IFMIB' => {
    ifType => {
      1 => 'other',
      2 => 'regular1822',
      3 => 'hdh1822',
      4 => 'ddnX25',
      5 => 'rfc877x25',
      6 => 'ethernetCsmacd',
      7 => 'iso88023Csmacd',
      8 => 'iso88024TokenBus',
      9 => 'iso88025TokenRing',
      10 => 'iso88026Man',
      11 => 'starLan',
      12 => 'proteon10Mbit',
      13 => 'proteon80Mbit',
      14 => 'hyperchannel',
      15 => 'fddi',
      16 => 'lapb',
      17 => 'sdlc',
      18 => 'ds1',
      19 => 'e1',
      20 => 'basicISDN',
      21 => 'primaryISDN',
      22 => 'propPointToPointSerial',
      23 => 'ppp',
      24 => 'softwareLoopback',
      25 => 'eon',
      26 => 'ethernet3Mbit',
      27 => 'nsip',
      28 => 'slip',
      29 => 'ultra',
      30 => 'ds3',
      31 => 'sip',
      32 => 'frameRelay',
      33 => 'rs232',
      34 => 'para',
      35 => 'arcnet',
      36 => 'arcnetPlus',
      37 => 'atm',
      38 => 'miox25',
      39 => 'sonet',
      40 => 'x25ple',
      41 => 'iso88022llc',
      42 => 'localTalk',
      43 => 'smdsDxi',
      44 => 'frameRelayService',
      45 => 'v35',
      46 => 'hssi',
      47 => 'hippi',
      48 => 'modem',
      49 => 'aal5',
      50 => 'sonetPath',
      51 => 'sonetVT',
      52 => 'smdsIcip',
      53 => 'propVirtual',
      54 => 'propMultiplexor',
      55 => 'ieee80212',
      56 => 'fibreChannel',
      57 => 'hippiInterface',
      58 => 'frameRelayInterconnect',
      59 => 'aflane8023',
      60 => 'aflane8025',
      61 => 'cctEmul',
      62 => 'fastEther',
      63 => 'isdn',
      64 => 'v11',
      65 => 'v36',
      66 => 'g703at64k',
      67 => 'g703at2mb',
      68 => 'qllc',
      69 => 'fastEtherFX',
      70 => 'channel',
      71 => 'ieee80211',
      72 => 'ibm370parChan',
      73 => 'escon',
      74 => 'dlsw',
      75 => 'isdns',
      76 => 'isdnu',
      77 => 'lapd',
      78 => 'ipSwitch',
      79 => 'rsrb',
      80 => 'atmLogical',
      81 => 'ds0',
      82 => 'ds0Bundle',
      83 => 'bsc',
      84 => 'async',
      85 => 'cnr',
      86 => 'iso88025Dtr',
      87 => 'eplrs',
      88 => 'arap',
      89 => 'propCnls',
      90 => 'hostPad',
      91 => 'termPad',
      92 => 'frameRelayMPI',
      93 => 'x213',
      94 => 'adsl',
      95 => 'radsl',
      96 => 'sdsl',
      97 => 'vdsl',
      98 => 'iso88025CRFPInt',
      99 => 'myrinet',
      100 => 'voiceEM',
      101 => 'voiceFXO',
      102 => 'voiceFXS',
      103 => 'voiceEncap',
      104 => 'voiceOverIp',
      105 => 'atmDxi',
      106 => 'atmFuni',
      107 => 'atmIma',
      108 => 'pppMultilinkBundle',
      109 => 'ipOverCdlc',
      110 => 'ipOverClaw',
      111 => 'stackToStack',
      112 => 'virtualIpAddress',
      113 => 'mpc',
      114 => 'ipOverAtm',
      115 => 'iso88025Fiber',
      116 => 'tdlc',
      117 => 'gigabitEthernet',
      118 => 'hdlc',
      119 => 'lapf',
      120 => 'v37',
      121 => 'x25mlp',
      122 => 'x25huntGroup',
      123 => 'transpHdlc',
      124 => 'interleave',
      125 => 'fast',
      126 => 'ip',
      127 => 'docsCableMaclayer',
      128 => 'docsCableDownstream',
      129 => 'docsCableUpstream',
      130 => 'a12MppSwitch',
      131 => 'tunnel',
      132 => 'coffee',
      133 => 'ces',
      134 => 'atmSubInterface',
      135 => 'l2vlan',
      136 => 'l3ipvlan',
      137 => 'l3ipxvlan',
      138 => 'digitalPowerline',
      139 => 'mediaMailOverIp',
      140 => 'dtm',
      141 => 'dcn',
      142 => 'ipForward',
      143 => 'msdsl',
      144 => 'ieee1394',
      145 => 'if-gsn',
      146 => 'dvbRccMacLayer',
      147 => 'dvbRccDownstream',
      148 => 'dvbRccUpstream',
      149 => 'atmVirtual',
      150 => 'mplsTunnel',
      151 => 'srp',
      152 => 'voiceOverAtm',
      153 => 'voiceOverFrameRelay',
      154 => 'idsl',
      155 => 'compositeLink',
      156 => 'ss7SigLink',
      157 => 'propWirelessP2P',
      158 => 'frForward',
      159 => 'rfc1483',
      160 => 'usb',
      161 => 'ieee8023adLag',
      162 => 'bgppolicyaccounting',
      163 => 'frf16MfrBundle',
      164 => 'h323Gatekeeper',
      165 => 'h323Proxy',
      166 => 'mpls',
      167 => 'mfSigLink',
      168 => 'hdsl2',
      169 => 'shdsl',
      170 => 'ds1FDL',
      171 => 'pos',
      172 => 'dvbAsiIn',
      173 => 'dvbAsiOut',
      174 => 'plc',
      175 => 'nfas',
      176 => 'tr008',
      177 => 'gr303RDT',
      178 => 'gr303IDT',
      179 => 'isup',
      180 => 'propDocsWirelessMaclayer',
      181 => 'propDocsWirelessDownstream',
      182 => 'propDocsWirelessUpstream',
      183 => 'hiperlan2',
      184 => 'propBWAp2Mp',
      185 => 'sonetOverheadChannel',
      186 => 'digitalWrapperOverheadChannel',
      187 => 'aal2',
      188 => 'radioMAC',
      189 => 'atmRadio',
      190 => 'imt',
      191 => 'mvl',
      192 => 'reachDSL',
      193 => 'frDlciEndPt',
      194 => 'atmVciEndPt',
      195 => 'opticalChannel',
      196 => 'opticalTransport',
      197 => 'propAtm',
      198 => 'voiceOverCable',
      199 => 'infiniband',
      200 => 'teLink',
      201 => 'q2931',
      202 => 'virtualTg',
      203 => 'sipTg',
      204 => 'sipSig',
      205 => 'docsCableUpstreamChannel',
      206 => 'econet',
      207 => 'pon155',
      208 => 'pon622',
      209 => 'bridge',
      210 => 'linegroup',
      211 => 'voiceEMFGD',
      212 => 'voiceFGDEANA',
      213 => 'voiceDID',
      214 => 'mpegTransport',
      215 => 'sixToFour',
      216 => 'gtp',
      217 => 'pdnEtherLoop1',
      218 => 'pdnEtherLoop2',
      219 => 'opticalChannelGroup',
      220 => 'homepna',
      221 => 'gfp',
      222 => 'ciscoISLvlan',
      223 => 'actelisMetaLOOP',
      224 => 'fcipLink',
      225 => 'rpr',
      226 => 'qam',
      227 => 'lmp',
      228 => 'cblVectaStar',
      229 => 'docsCableMCmtsDownstream',
      230 => 'adsl2',
      231 => 'macSecControlledIF',
      232 => 'macSecUncontrolledIF',
      233 => 'aviciOpticalEther',
      234 => 'atmbond',
      235 => 'voiceFGDOS',
      236 => 'mocaVersion1',
      237 => 'ieee80216WMAN',
      238 => 'adsl2plus',
      239 => 'dvbRcsMacLayer',
      240 => 'dvbTdm',
      241 => 'dvbRcsTdma',
      242 => 'x86Laps',
      243 => 'wwanPP',
      244 => 'wwanPP2',
      245 => 'voiceEBS',
      246 => 'ifPwType',
      247 => 'ilan',
      248 => 'pip',
      249 => 'aluELP',
      250 => 'gpon',
      251 => 'vdsl2',
      252 => 'capwapDot11Profile',
      253 => 'capwapDot11Bss',
      254 => 'capwapWtpVirtualRadio',
      255 => 'bits',
      256 => 'docsCableUpstreamRfPort',
      257 => 'cableDownstreamRfPort',
      258 => 'vmwareVirtualNic',
      259 => 'ieee802154',
      260 => 'otnOdu',
      261 => 'otnOtu',
      262 => 'ifVfiType',
      263 => 'g9981',
      264 => 'g9982',
      265 => 'g9983',
      266 => 'aluEpon',
      267 => 'aluEponOnu',
      268 => 'aluEponPhysicalUni',
      269 => 'aluEponLogicalLink',
      270 => 'aluGponOnu',
      271 => 'aluGponPhysicalUni',
      272 => 'vmwareNicTeam',
      # 273 ... http://tools.ietf.org/html/rfc6825
    },
  },
  'ENTITY-MIB' => {
    'PhysicalClass' => {
      1 => 'other',
      2 => 'unknown',
      3 => 'chassis',
      4 => 'backplane',
      5 => 'container',
      6 => 'powerSupply',
      7 => 'fan',
      8 => 'sensor',
      9 => 'module',
      10 => 'port',
      11 => 'stack',
      12 => 'cpu',
    },
  },
  'CISCO-IETF-NAT-MIB' => {
    'NATProtocolType' => {
      1 => 'other',
      2 => 'icmp',
      3 => 'udp',
      4 => 'tcp',
    },
  },
  'CISCO-ENTITY-ALARM-MIB' => {
    'AlarmSeverity' => {
      1 => 'critical',
      2 => 'major',
      3 => 'minor',
      4 => 'info',
    },
    'AlarmSeverityOrZero' => {
      0 => 'none',
      1 => 'critical',
      2 => 'major',
      3 => 'minor',
      4 => 'info',
    },
  },
  'CISCO-FEATURE-CONTROL-MIB' => {
    'CiscoOptionalFeature' => {
      1 => 'ivr',
      2 => 'fcip',
      3 => 'fcsp',
      4 => 'ficon',
      5 => 'iscsi',
      6 => 'tacacs',
      7 => 'qosManager',
      8 => 'portSecurity',
      9 => 'fabricBinding',
      10 => 'iscsiInterfaceVsanMembership',
      11 => 'ike',
      12 => 'isns',
      13 => 'ipSec',
      14 => 'portTracker',
      15 => 'scheduler',
      16 => 'npiv',
      17 => 'sanExtTuner',
      18 => 'dpvm',
      19 => 'extenedCredit',
    },
    'CiscoFeatureAction' => {
      1 => 'noOp',
      2 => 'enable',
      3 => 'disable',
    },
    'CiscoFeatureStatus' => {
      1 => 'unknown',
      2 => 'enabled',
      3 => 'disabled',
    },
    'CiscoFeatureActionResult' => {
      1 => 'none',
      2 => 'actionSuccess',
      3 => 'actionFailed',
      4 => 'actionInProgress',
    },
  },
  'CISCO-IPSEC-FLOW-MONITOR-MIB' => {
    AuthAlgo => {
      '1' => 'none',
      '2' => 'hmacMd5',
      '3' => 'hmacSha',
    },
    CompAlgo => {
      '1' => 'none',
      '2' => 'ldf',
    },
    DiffHellmanGrp => {
      '1' => 'none',
      '2' => 'dhGroup1',
      '3' => 'dhGroup2',
    },
    EncapMode => {
      '1' => 'tunnel',
      '2' => 'transport',
    },
    EncryptAlgo => {
      '1' => 'none',
      '2' => 'des',
      '3' => 'des3',
    },
    EndPtType => {
      '1' => 'singleIpAddr',
      '2' => 'ipAddrRange',
      '3' => 'ipSubnet',
    },
    IkeAuthMethod => {
      '1' => 'none',
      '2' => 'preSharedKey',
      '3' => 'rsaSig',
      '4' => 'rsaEncrypt',
      '5' => 'revPublicKey',
    },
    IkeHashAlgo => {
      '1' => 'none',
      '2' => 'md5',
      '3' => 'sha',
    },
    IkeNegoMode => {
      '1' => 'main',
      '2' => 'aggressive',
    },
    IkePeerType => {
      '1' => 'ipAddrPeer',
      '2' => 'namePeer',
    },
    KeyType => {
      '1' => 'ike',
      '2' => 'manual',
    },
    TrapStatus => {
      '1' => 'enabled',
      '2' => 'disabled',
    },
    TunnelStatus => {
      '1' => 'active',
      '2' => 'destroy',
    },
    cikeFailReason => {
      '1' => 'other',
      '2' => 'peerDelRequest',
      '3' => 'peerLost',
      '4' => 'localFailure',
      '5' => 'authFailure',
      '6' => 'hashValidation',
      '7' => 'encryptFailure',
      '8' => 'internalError',
      '9' => 'sysCapExceeded',
      '10' => 'proposalFailure',
      '11' => 'peerCertUnavailable',
      '12' => 'peerCertNotValid',
      '13' => 'localCertExpired',
      '14' => 'crlFailure',
      '15' => 'peerEncodingError',
      '16' => 'nonExistentSa',
      '17' => 'operRequest',
    },
    cikeTunHistTermReason => {
      '1' => 'other',
      '2' => 'normal',
      '3' => 'operRequest',
      '4' => 'peerDelRequest',
      '5' => 'peerLost',
      '6' => 'localFailure',
      '7' => 'checkPointReg',
    },
    cipSecFailReason => {
      '1' => 'other',
      '2' => 'internalError',
      '3' => 'peerEncodingError',
      '4' => 'proposalFailure',
      '5' => 'protocolUseFail',
      '6' => 'nonExistentSa',
      '7' => 'decryptFailure',
      '8' => 'encryptFailure',
      '9' => 'inAuthFailure',
      '10' => 'outAuthFailure',
      '11' => 'compression',
      '12' => 'sysCapExceeded',
      '13' => 'peerDelRequest',
      '14' => 'peerLost',
      '15' => 'seqNumRollOver',
      '16' => 'operRequest',
    },
    cipSecHistCheckPoint => {
      '1' => 'ready',
      '2' => 'checkPoint',
    },
    cipSecSpiDirection => {
      '1' => 'in',
      '2' => 'out',
    },
    cipSecSpiProtocol => {
      '1' => 'ah',
      '2' => 'esp',
      '3' => 'ipcomp',
    },
    cipSecSpiStatus => {
      '1' => 'active',
      '2' => 'expiring',
    },
    cipSecTunHistTermReason => {
      '1' => 'other',
      '2' => 'normal',
      '3' => 'operRequest',
      '4' => 'peerDelRequest',
      '5' => 'peerLost',
      '6' => 'seqNumRollOver',
      '7' => 'checkPointReq',
    },
  },
  'CISCO-ETHERNET-FABRIC-EXTENDER-MIB' => {
    CiscoPortPinningMode => {
      '1' => 'static',
    },
  },
  'OSPF-MIB' => {
    'Status' => {
      1 => 'enabled',
      2 => 'disabled',
    },
    ospfAreaAggregateEffect => {
      '1' => 'advertiseMatching',
      '2' => 'doNotAdvertiseMatching',
    },
    ospfIfState => {
      '1' => 'down',
      '2' => 'loopback',
      '3' => 'waiting',
      '4' => 'pointToPoint',
      '5' => 'designatedRouter',
      '6' => 'backupDesignatedRouter',
      '7' => 'otherDesignatedRouter',
    },
    ospfExtLsdbType => {
      '5' => 'asExternalLink',
    },
    ospfAreaSummary => {
      '1' => 'noAreaSummary',
      '2' => 'sendAreaSummary',
    },
    ospfAreaRangeEffect => {
      '1' => 'advertiseMatching',
      '2' => 'doNotAdvertiseMatching',
    },
    ospfImportAsExtern => {
      '1' => 'importExternal',
      '2' => 'importNoExternal',
      '3' => 'importNssa',
    },
    ospfAreaLsaCountLsaType => {
      '1' => 'routerLink',
      '2' => 'networkLink',
      '3' => 'summaryLink',
      '4' => 'asSummaryLink',
      '6' => 'multicastLink',
      '7' => 'nssaExternalLink',
      '10' => 'areaOpaqueLink',
    },
    ospfNbrRestartHelperExitReason => {
      '1' => 'none',
      '2' => 'inProgress',
      '3' => 'completed',
      '4' => 'timedOut',
      '5' => 'topologyChanged',
    },
    ospfRestartStatus => {
      '1' => 'notRestarting',
      '2' => 'plannedRestart',
      '3' => 'unplannedRestart',
    },
    ospfStubRouterAdvertisement => {
      '1' => 'doNotAdvertise',
      '2' => 'advertise',
    },
    ospfVirtNbrRestartHelperExitReason => {
      '1' => 'none',
      '2' => 'inProgress',
      '3' => 'completed',
      '4' => 'timedOut',
      '5' => 'topologyChanged',
    },
    ospfNbrRestartHelperStatus => {
      '1' => 'notHelping',
      '2' => 'helping',
    },
    ospfVirtLocalLsdbType => {
      '9' => 'localOpaqueLink',
    },
    ospfNbrState => {
      '1' => 'down',
      '2' => 'attempt',
      '3' => 'init',
      '4' => 'twoWay',
      '5' => 'exchangeStart',
      '6' => 'exchange',
      '7' => 'loading',
      '8' => 'full',
    },
    ospfVirtIfState => {
      '1' => 'down',
      '4' => 'pointToPoint',
    },
    ospfLsdbType => {
      '1' => 'routerLink',
      '2' => 'networkLink',
      '3' => 'summaryLink',
      '4' => 'asSummaryLink',
      '5' => 'asExternalLink',
      '6' => 'multicastLink',
      '7' => 'nssaExternalLink',
      '10' => 'areaOpaqueLink',
    },
    ospfAreaAggregateLsdbType => {
      '3' => 'summaryLink',
      '7' => 'nssaExternalLink',
    },
    ospfIfMulticastForwarding => {
      '1' => 'blocked',
      '2' => 'multicast',
      '3' => 'unicast',
    },
    ospfVersionNumber => {
      '2' => 'version2',
    },
    ospfRestartSupport => {
      '1' => 'none',
      '2' => 'plannedOnly',
      '3' => 'plannedAndUnplanned',
    },
    ospfStubMetricType => {
      '1' => 'ospfMetric',
      '2' => 'comparableCost',
      '3' => 'nonComparable',
    },
    ospfIfType => {
      '1' => 'broadcast',
      '2' => 'nbma',
      '3' => 'pointToPoint',
      '5' => 'pointToMultipoint',
    },
    ospfAreaNssaTranslatorState => {
      '1' => 'enabled',
      '2' => 'elected',
      '3' => 'disabled',
    },
    ospfRestartExitReason => {
      '1' => 'none',
      '2' => 'inProgress',
      '3' => 'completed',
      '4' => 'timedOut',
      '5' => 'topologyChanged',
    },
    ospfLocalLsdbType => {
      '9' => 'localOpaqueLink',
    },
    ospfVirtNbrState => {
      '1' => 'down',
      '2' => 'attempt',
      '3' => 'init',
      '4' => 'twoWay',
      '5' => 'exchangeStart',
      '6' => 'exchange',
      '7' => 'loading',
      '8' => 'full',
    },
    ospfNbmaNbrPermanence => {
      '1' => 'dynamic',
      '2' => 'permanent',
    },
    ospfAsLsdbType => {
      '5' => 'asExternalLink',
      '11' => 'asOpaqueLink',
    },
    ospfVirtNbrRestartHelperStatus => {
      '1' => 'notHelping',
      '2' => 'helping',
    },
    ospfAreaNssaTranslatorRole => {
      '1' => 'always',
      '2' => 'candidate',
    },
    'AuType' => { # rfc2328 appendix e.
      '0' => 'Null authentication',
      '1' => 'Simple password',
      # others assigned by iana
    },
    'ospfVirtNbrOptions' => sub {
      my $value = shift;
      my @capabilities = ();
      push (@capabilities, 'only TOS 0') if $value & (1<<0) == 0;
      push (@capabilities, 'all except TOS 0') if $value & (1<<0) == 1;
      push (@capabilities, 'multicast') if $value & (1<<1) == 1;
      return join(',', @capabilities);
    },
  },
  'RFC4001-MIB' => {
    'inetAddressType' => {
      0 => 'unknown',
      1 => 'ipv4',
      2 => 'ipv6',
      3 => 'ipv4z',
      4 => 'ipv6z',
      16 => 'dns',
    },
    # https://www.ietf.org/rfc/rfc4001.txt
    'inetAddress' => sub {
      my $type = shift;
      my @params = @_;
      if ($type eq "ipv4") {
        return 0;
      }
    },
    'InetAddressPrefixLength ' => sub {
      my $type = shift;
      my @params = @_;
      if ($type eq "ipv4") {
        return 0;
      }
    },
  }
};

package Classes::Device;
our @ISA = qw(Monitoring::GLPlugin::SNMP Monitoring::GLPlugin::UPNP);
use strict;

sub classify {
  my $self = shift;
  if (! ($self->opts->hostname || $self->opts->snmpwalk)) {
    $self->add_unknown('either specify a hostname or a snmpwalk file');
  } else {
    if ($self->opts->servertype && $self->opts->servertype eq 'linuxlocal') {
    } elsif ($self->opts->servertype && $self->opts->servertype eq 'windowslocal') {
      eval "use DBD::WMI";
      if ($@) {
        $self->add_unknown("module DBD::WMI is not installed");
      }
    } elsif ($self->opts->port && $self->opts->port == 49000) {
      $self->{productname} = 'upnp';
      $self->check_upnp_and_model();
    } else {
      $self->check_snmp_and_model();
    }
    if ($self->opts->servertype) {
      $self->{productname} = $self->opts->servertype;
      $self->{productname} = 'cisco' if $self->opts->servertype eq 'cisco';
      $self->{productname} = 'huawei' if $self->opts->servertype eq 'huawei';
      $self->{productname} = 'hp' if $self->opts->servertype eq 'hp';
      $self->{productname} = 'brocade' if $self->opts->servertype eq 'brocade';
      $self->{productname} = 'netscreen' if $self->opts->servertype eq 'netscreen';
      $self->{productname} = 'linuxlocal' if $self->opts->servertype eq 'linuxlocal';
      $self->{productname} = 'procurve' if $self->opts->servertype eq 'procurve';
      $self->{productname} = 'bluecoat' if $self->opts->servertype eq 'bluecoat';
      $self->{productname} = 'checkpoint' if $self->opts->servertype eq 'checkpoint';
      $self->{productname} = 'clavister' if $self->opts->servertype eq 'clavister';
      $self->{productname} = 'ifmib' if $self->opts->servertype eq 'ifmib';
    }
    if (! $self->check_messages()) {
      if ($self->opts->verbose && $self->opts->verbose) {
        printf "I am a %s\n", $self->{productname};
      }
      if ($self->opts->mode =~ /^my-/) {
        $self->load_my_extension();
      } elsif ($self->{productname} =~ /upnp/i) {
        bless $self, 'Classes::UPNP';
        $self->debug('using Classes::UPNP');
      } elsif ($self->{productname} =~ /FRITZ/i) {
        bless $self, 'Classes::UPNP::AVM';
        $self->debug('using Classes::UPNP::AVM');
      } elsif ($self->{productname} =~ /linuxlocal/i) {
        bless $self, 'Server::Linux';
        $self->debug('using Server::Linux');
      } elsif ($self->{productname} =~ /windowslocal/i) {
        bless $self, 'Server::Windows';
        $self->debug('using Server::Windows');
      } elsif ($self->{productname} =~ /Cisco/i) {
        bless $self, 'Classes::Cisco';
        $self->debug('using Classes::Cisco');
      } elsif ($self->{productname} =~ /fujitsu intelligent blade panel 30\/12/i) {
        bless $self, 'Classes::Cisco';
        $self->debug('using Classes::Cisco');
      } elsif ($self->{productname} =~ /UCOS /i) {
        bless $self, 'Classes::Cisco';
        $self->debug('using Classes::Cisco');
      } elsif ($self->{productname} =~ /Nortel/i) {
        bless $self, 'Classes::Nortel';
        $self->debug('using Classes::Nortel');
      } elsif ($self->{productname} =~ /AT-GS/i) {
        bless $self, 'Classes::AlliedTelesyn';
        $self->debug('using Classes::AlliedTelesyn');
      } elsif ($self->{productname} =~ /AT-\d+GB/i) {
        bless $self, 'Classes::AlliedTelesyn';
        $self->debug('using Classes::AlliedTelesyn');
      } elsif ($self->{productname} =~ /Allied Telesyn Ethernet Switch/i) {
        bless $self, 'Classes::AlliedTelesyn';
        $self->debug('using Classes::AlliedTelesyn');
      } elsif ($self->{productname} =~ /Linux cumulus/i) {
        bless $self, 'Classes::Cumulus';
        $self->debug('using Classes::Cumulus');
      } elsif ($self->{productname} =~ /DS_4100/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /Connectrix DS_4900B/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /EMC\s*DS.*4700M/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /EMC\s*DS-24M2/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /Brocade/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /Fibre Channel Switch/i) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{productname} =~ /Juniper.*MAG\-\d+/i) {
        # Juniper Networks,Inc,MAG-4610,7.2R10
        bless $self, 'Classes::Juniper';
        $self->debug('using Classes::Juniper');
      } elsif ($self->{productname} =~ /Juniper.*MAG\-SM\d+/i) {
        # Juniper Networks,Inc,MAG-SMx60,7.4R8
        bless $self, 'Classes::Juniper::IVE';
        $self->debug('using Classes::Juniper::IVE');
      } elsif ($self->{productname} =~ /NetScreen/i) {
        bless $self, 'Classes::Juniper';
        $self->debug('using Classes::Juniper');
      } elsif ($self->implements_mib('NETGEAR-MIB')) {
        $self->debug('using Classes::Netgear');
        bless $self, 'Classes::Netgear';
      } elsif ($self->{productname} =~ /^(GS|FS)/i) {
        bless $self, 'Classes::Juniper';
        $self->debug('using Classes::Juniper');
      } elsif ($self->implements_mib('NETSCREEN-PRODUCTS-MIB')) {
        $self->debug('using Classes::Juniper::NetScreen');
        bless $self, 'Classes::Juniper::NetScreen';
      } elsif ($self->implements_mib('PAN-PRODUCTS-MIB')) {
        $self->debug('using Classes::PaloAlto');
        bless $self, 'Classes::PaloAlto';
      } elsif ($self->{productname} =~ /SecureOS/i) {
        bless $self, 'Classes::SecureOS';
        $self->debug('using Classes::SecureOS');
      } elsif ($self->{productname} =~ /Linux.*((el6.f5.x86_64)|(el5.1.0.f5app)) .*/i) {
        bless $self, 'Classes::F5';
        $self->debug('using Classes::F5');
      } elsif ($self->{productname} =~ /Procurve/i) {
        bless $self, 'Classes::HP';
        $self->debug('using Classes::HP');
      } elsif ($self->{productname} =~ /(cpx86_64)|(Check\s*Point)|(Linux.*\dcp )/i) {
        bless $self, 'Classes::CheckPoint';
        $self->debug('using Classes::CheckPoint');
      } elsif ($self->{productname} =~ /Clavister/i) {
        bless $self, 'Classes::Clavister';
        $self->debug('using Classes::Clavister');
      } elsif ($self->{productname} =~ /Blue\s*Coat/i) {
        bless $self, 'Classes::Bluecoat';
        $self->debug('using Classes::Bluecoat');
      } elsif ($self->{productname} =~ /Foundry/i) {
        bless $self, 'Classes::Foundry';
        $self->debug('using Classes::Foundry');
      } elsif ($self->{productname} =~ /IronWare/i) {
        # although there can be a 
        # Brocade Communications Systems, Inc. FWS648, IronWare Version 07.1....
        bless $self, 'Classes::Foundry';
        $self->debug('using Classes::Foundry');
      } elsif ($self->{productname} =~ /Linux Stingray/i) {
        bless $self, 'Classes::HOSTRESOURCESMIB';
        $self->debug('using Classes::HOSTRESOURCESMIB');
      } elsif ($self->{productname} =~ /Fortinet|Fortigate/i) {
        bless $self, 'Classes::Fortigate';
        $self->debug('using Classes::Fortigate');
      } elsif ($self->{productname} eq "ifmib") {
        bless $self, 'Classes::Generic';
        $self->debug('using Classes::Generic');
      } elsif ($self->implements_mib('SW-MIB')) {
        bless $self, 'Classes::Brocade';
        $self->debug('using Classes::Brocade');
      } elsif ($self->{sysobjectid} =~ /1\.3\.6\.1\.4\.1\.9\./) {
        bless $self, 'Classes::Cisco';
        $self->debug('using Classes::Cisco');
      } else {
        if (my $class = $self->discover_suitable_class()) {
          bless $self, $class;
          $self->debug('using '.$class);
        } else {
          bless $self, 'Classes::Generic';
          $self->debug('using Classes::Generic');
        }
      }
    }
  }
  return $self;
}


package Classes::Generic;
our @ISA = qw(Classes::Device);
use strict;


sub init {
  my $self = shift;
  if ($self->mode =~ /device::interfaces::aggregation::availability/) {
    $self->analyze_and_check_aggregation_subsystem("Classes::IFMIB::Component::LinkAggregation");
  } elsif ($self->mode =~ /device::interfaces/) {
    $self->analyze_and_check_interface_subsystem("Classes::IFMIB::Component::InterfaceSubsystem");
  } elsif ($self->mode =~ /device::routes/) {
    if ($self->implements_mib('IP-FORWARD-MIB')) {
      $self->analyze_and_check_interface_subsystem("Classes::IPFORWARDMIB::Component::RoutingSubsystem");
    } else {
      $self->analyze_and_check_interface_subsystem("Classes::IPMIB::Component::RoutingSubsystem");
    }
  } elsif ($self->mode =~ /device::bgp/) {
    $self->analyze_and_check_bgp_subsystem("Classes::BGP::Component::PeerSubsystem");
  } elsif ($self->mode =~ /device::ospf/) {
    bless $self, "Classes::OSPF";
    #$self->analyze_and_check_ospf_subsystem("Classes::OSPF");
    $self->init();
  } else {
    bless $self, 'Monitoring::GLPlugin::SNMP';
    $self->no_such_mode();
  }
}

package main;
# /usr/bin/perl -w

use strict;
no warnings qw(once);


eval {
  if ( ! grep /AUTOLOAD/, keys %Monitoring::GLPlugin::) {
    require "Monitoring::GLPlugin";
    require "Monitoring::GLPlugin::SNMP";
    require "Monitoring::GLPlugin::UPNP";
  }
};
if ($@) {
  printf "UNKNOWN - module Monitoring::GLPlugin was not found. Either build a standalone version of this plugin or set PERL5LIB\n";
  printf "%s\n", $@;
  exit 3;
}

my $plugin = Classes::Device->new(
    shortname => '',
    usage => 'Usage: %s [ -v|--verbose ] [ -t <timeout> ] '.
        '--mode <what-to-do> '.
        '--hostname <network-component> --community <snmp-community>'.
        '  ...]',
    version => '$Revision: 4.1 $',
    blurb => 'This plugin checks various parameters of network components ',
    url => 'http://labs.consol.de/nagios/check_nwc_health',
    timeout => 60,
    plugin => $Monitoring::GLPlugin::pluginname,
);
$plugin->add_mode(
    internal => 'device::uptime',
    spec => 'uptime',
    alias => undef,
    help => 'Check the uptime of the device',
);
$plugin->add_mode(
    internal => 'device::hardware::health',
    spec => 'hardware-health',
    alias => undef,
    help => 'Check the status of environmental equipment (fans, temperatures, power)',
);
$plugin->add_mode(
    internal => 'device::hardware::load',
    spec => 'cpu-load',
    alias => ['cpu-usage'],
    help => 'Check the CPU load of the device',
);
$plugin->add_mode(
    internal => 'device::hardware::memory',
    spec => 'memory-usage',
    alias => undef,
    help => 'Check the memory usage of the device',
);
$plugin->add_mode(
    internal => 'device::interfaces::usage',
    spec => 'interface-usage',
    alias => undef,
    help => 'Check the utilization of interfaces',
);
$plugin->add_mode(
    internal => 'device::interfaces::errors',
    spec => 'interface-errors',
    alias => undef,
    help => 'Check the error-rate of interfaces (without discards)',
);
$plugin->add_mode(
    internal => 'device::interfaces::discards',
    spec => 'interface-discards',
    alias => undef,
    help => 'Check the discard-rate of interfaces',
);
$plugin->add_mode(
    internal => 'device::interfaces::operstatus',
    spec => 'interface-status',
    alias => undef,
    help => 'Check the status of interfaces (oper/admin)',
);
$plugin->add_mode(
    internal => 'device::interfaces::nat::sessions::count',
    spec => 'interface-nat-count-sessions',
    alias => undef,
    help => 'Count the number of nat sessions',
);
$plugin->add_mode(
    internal => 'device::interfaces::nat::rejects',
    spec => 'interface-nat-rejects',
    alias => undef,
    help => 'Count the number of nat sessions rejected due to lack of resources',
);
$plugin->add_mode(
    internal => 'device::interfaces::list',
    spec => 'list-interfaces',
    alias => undef,
    help => 'Show the interfaces of the device and update the name cache',
);
$plugin->add_mode(
    internal => 'device::interfaces::listdetail',
    spec => 'list-interfaces-detail',
    alias => undef,
    help => 'Show the interfaces of the device and some details',
);
$plugin->add_mode(
    internal => 'device::interfaces::availability',
    spec => 'interface-availability',
    alias => undef,
    help => 'Show the availability (oper != up) of interfaces',
);
$plugin->add_mode(
    internal => 'device::interfaces::aggregation::availability',
    spec => 'link-aggregation-availability',
    alias => undef,
    help => 'Check the percentage of up interfaces in a link aggregation',
);
$plugin->add_mode(
    internal => 'device::routes::list',
    spec => 'list-routes',
    alias => undef,
    help => 'Show the configured routes',
    help => 'Check the percentage of up interfaces in a link aggregation',
);
$plugin->add_mode(
    internal => 'device::routes::exists',
    spec => 'route-exists',
    alias => undef,
    help => 'Check if a route exists. (--name is the dest, --name2 check also the next hop)',
);
$plugin->add_mode(
    internal => 'device::routes::count',
    spec => 'count-routes',
    alias => undef,
    help => 'Count the routes. (--name is the dest, --name2 is the hop)',
);
$plugin->add_mode(
    internal => 'device::vpn::status',
    spec => 'vpn-status',
    alias => undef,
    help => 'Check the status of vpns (up/down)',
);
$plugin->add_mode(
    internal => 'device::shinken::interface',
    spec => 'create-shinken-service',
    alias => undef,
    help => 'Create a Shinken service definition',
);
$plugin->add_mode(
    internal => 'device::hsrp::state',
    spec => 'hsrp-state',
    alias => undef,
    help => 'Check the state in a HSRP group',
);
$plugin->add_mode(
    internal => 'device::hsrp::failover',
    spec => 'hsrp-failover',
    alias => undef,
    help => 'Check if a HSRP group\'s nodes have changed their roles',
);
$plugin->add_mode(
    internal => 'device::hsrp::list',
    spec => 'list-hsrp-groups',
    alias => undef,
    help => 'Show the HSRP groups configured on this device',
);
$plugin->add_mode(
    internal => 'device::bgp::peer::status',
    spec => 'bgp-peer-status',
    alias => undef,
    help => 'Check status of BGP peers',
);
$plugin->add_mode(
    internal => 'device::bgp::peer::count',
    spec => 'count-bgp-peers',
    alias => undef,
    help => 'Count the number of BGP peers',
);
$plugin->add_mode(
    internal => 'device::bgp::peer::watch',
    spec => 'watch-bgp-peers',
    alias => undef,
    help => 'Watch BGP peers appear and disappear',
);
$plugin->add_mode(
    internal => 'device::bgp::peer::list',
    spec => 'list-bgp-peers',
    alias => undef,
    help => 'Show BGP peers known to this device',
);
$plugin->add_mode(
    internal => 'device::bgp::prefix::count',
    spec => 'count-bgp-prefixes',
    alias => undef,
    help => 'Count the number of BGP prefixes (for specific peer with --name)',
);
$plugin->add_mode(
    internal => 'device::ospf::neighbor::status',
    spec => 'ospf-neighbor-status',
    alias => undef,
    help => 'Check status of OSPF neighbors',
);
$plugin->add_mode(
    internal => 'device::ospf::neighbor::list',
    spec => 'list-ospf-neighbors',
    alias => undef,
    help => 'Show OSPF neighbors',
);
$plugin->add_mode(
    internal => 'device::ha::role',
    spec => 'ha-role',
    alias => undef,
    help => 'Check the role in a ha group',
);
$plugin->add_mode(
    internal => 'device::svn::status',
    spec => 'svn-status',
    alias => undef,
    help => 'Check the status of the svn subsystem',
);
$plugin->add_mode(
    internal => 'device::mngmt::status',
    spec => 'mngmt-status',
    alias => undef,
    help => 'Check the status of the management subsystem',
);
$plugin->add_mode(
    internal => 'device::fw::policy::installed',
    spec => 'fw-policy',
    alias => undef,
    help => 'Check the installed firewall policy',
);
$plugin->add_mode(
    internal => 'device::fw::policy::connections',
    spec => 'fw-connections',
    alias => undef,
    help => 'Check the number of firewall policy connections',
);
$plugin->add_mode(
    internal => 'device::lb::session::usage',
    spec => 'session-usage',
    alias => undef,
    help => 'Check the session limits of a load balancer',
);
$plugin->add_mode(
    internal => 'device::security',
    spec => 'security-status',
    alias => undef,
    help => 'Check if there are security-relevant incidents',
);
$plugin->add_mode(
    internal => 'device::lb::pool::completeness',
    spec => 'pool-completeness',
    alias => undef,
    help => 'Check the members of a load balancer pool',
);
$plugin->add_mode(
    internal => 'device::lb::pool::connections',
    spec => 'pool-connections',
    alias => undef,
    help => 'Check the number of connections of a load balancer pool',
);
$plugin->add_mode(
    internal => 'device::lb::pool::complections',
    spec => 'pool-complections',
    alias => undef,
    help => 'Check the members and connections of a load balancer pool',
);
$plugin->add_mode(
    internal => 'device::lb::pool::list',
    spec => 'list-pools',
    alias => undef,
    help => 'List load balancer pools',
);
$plugin->add_mode(
    internal => 'device::licenses::validate',
    spec => 'check-licenses',
    alias => undef,
    help => 'Check the installed licences/keys',
);
$plugin->add_mode(
    internal => 'device::users::count',
    spec => 'count-users',
    alias => ['count-sessions', 'count-connections'],
    help => 'Count the (connected) users/sessions',
);
$plugin->add_mode(
    internal => 'device::config::status',
    spec => 'check-config',
    alias => undef,
    help => 'Check the status of configs (cisco, unsaved config changes)',
);
$plugin->add_mode(
    internal => 'device::connections::check',
    spec => 'check-connections',
    alias => undef,
    help => 'Check the quality of connections',
);
$plugin->add_mode(
    internal => 'device::connections::count',
    spec => 'count-connections',
    alias => ['count-connections-client', 'count-connections-server'],
    help => 'Check the number of connections (-client, -server is possible)',
);
$plugin->add_mode(
    internal => 'device::cisco::fex::watch',
    spec => 'watch-fexes',
    alias => undef,
    help => 'Check if FEXes appear and disappear (use --lookup)',
);
$plugin->add_mode(
    internal => 'device::wlan::aps::status',
    spec => 'accesspoint-status',
    alias => undef,
    help => 'Check the status of access points',
);
$plugin->add_mode(
    internal => 'device::wlan::aps::count',
    spec => 'count-accesspoints',
    alias => undef,
    help => 'Check if the number of access points is within a certain range',
);
$plugin->add_mode(
    internal => 'device::wlan::aps::watch',
    spec => 'watch-accesspoints',
    alias => undef,
    help => 'Check if access points appear and disappear (use --lookup)',
);
$plugin->add_mode(
    internal => 'device::wlan::aps::list',
    spec => 'list-accesspoints',
    alias => undef,
    help => 'List access points managed by this device',
);
$plugin->add_mode(
    internal => 'device::phone::cmstatus',
    spec => 'phone-cm-status',
    alias => undef,
    help => 'Check if the callmanager is up',
);
$plugin->add_mode(
    internal => 'device::phone::status',
    spec => 'phone-status',
    alias => undef,
    help => 'Check the number of registered/unregistered/rejected phones',
);
$plugin->add_mode(
    internal => 'device::smarthome::device::list',
    spec => 'list-smart-home-devices',
    alias => undef,
    help => 'List Fritz!DECT 200 plugs managed by this device',
);
$plugin->add_mode(
    internal => 'device::smarthome::device::status',
    spec => 'smart-home-device-status',
    alias => undef,
    help => 'Check if a Fritz!DECT 200 plug is on',
);
$plugin->add_mode(
    internal => 'device::smarthome::device::energy',
    spec => 'smart-home-device-energy',
    alias => undef,
    help => 'Show the current power consumption of a Fritz!DECT 200 plug',
);
$plugin->add_mode(
    internal => 'device::smarthome::device::consumption',
    spec => 'smart-home-device-consumption',
    alias => undef,
    help => 'Show the cumulated power consumption of a Fritz!DECT 200 plug',
);
$plugin->add_mode(
    internal => 'device::walk',
    spec => 'walk',
    alias => undef,
    help => 'Show snmpwalk command with the oids necessary for a simulation',
);
$plugin->add_mode(
    internal => 'device::supportedmibs',
    spec => 'supportedmibs',
    alias => undef,
    help => 'Shows the names of the mibs which this devices has implemented (only lausser may run this command)',
);
$plugin->add_snmp_args();
$plugin->add_default_args();
$plugin->mod_arg("name",
    help => "--name
   The name of an interface (ifDescr) or pool or ...",
);
$plugin->add_arg(
    spec => 'alias=s',
    help => "--alias
   The alias name of a 64bit-interface (ifAlias)",
    required => 0,
);
$plugin->add_arg(
    spec => 'ifspeedin=i',
    help => "--ifspeedin
   Override the ifspeed oid of an interface (only inbound)",
    required => 0,
);
$plugin->add_arg(
    spec => 'ifspeedout=i',
    help => "--ifspeedout
   Override the ifspeed oid of an interface (only outbound)",
    required => 0,
);
$plugin->add_arg(
    spec => 'ifspeed=i',
    help => "--ifspeed
   Override the ifspeed oid of an interface",
    required => 0,
);
$plugin->add_arg(
    spec => 'role=s',
    help => "--role
   The role of this device in a hsrp group (active/standby/listen)",
    required => 0,
);
$plugin->add_arg(
    spec => 'servertype=s',
    help => '--servertype
   The type of the network device: cisco (default). Use it if auto-detection
   is not possible',
    required => 0,
);

$plugin->getopts();
$plugin->classify();
$plugin->validate_args();

if (! $plugin->check_messages()) {
  $plugin->init();
  if (! $plugin->check_messages()) {
    $plugin->add_ok($plugin->get_summary())
        if $plugin->get_summary();
    $plugin->add_ok($plugin->get_extendedinfo(" "))
        if $plugin->get_extendedinfo();
  }
} elsif ($plugin->opts->snmpwalk && $plugin->opts->offline) {
  ;
} else {
  $plugin->add_critical('wrong device');
}
my ($code, $message) = $plugin->opts->multiline ?
    $plugin->check_messages(join => "\n", join_all => ', ') :
    $plugin->check_messages(join => ', ', join_all => ', ');
$message .= sprintf "\n%s\n", $plugin->get_info("\n")
    if $plugin->opts->verbose >= 1;
#printf "%s\n", Data::Dumper::Dumper($plugin);

$plugin->nagios_exit($code, $message);
printf "schluss\n";

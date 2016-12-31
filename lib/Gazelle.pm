package Gazelle;

use v5.016;
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Log::Log4perl ':no_extra_logdie_message';
use URI::Escape;
use LWP::UserAgent;
use HTTP::Cookies;
use JSON 'decode_json';
use Data::Dumper;

use constant {
  GZ_DEAD  => 0, # interface became inactive, login expired / etc
  GZ_NEW   => 1, # interface not yet logged in
  GZ_ALIVE => 2, # interface logged in successfully / ready
};

our $VERSION = '1.0.0';
our %GZ_REG; # to track unique instances

sub new {
  my ($class, %args) = @_;
  my $log            = Log::Log4perl->get_logger('gazelle.intf.new');
  my $obj            = bless { }, $class;
  my $error          = 0;

  foreach my $key (qw[ident api_base cookie_jar username password]) {
    unless (defined $args{$key}) {
      $log->error(sprintf('attempted to instantiate gazelle interface "%s" without mandatory key "%s"', ($args{ident} // 'unknown'), $key));
      $error++;
    }
    $obj->{$key} = $args{$key};
  }

  if (defined $GZ_REG{ $obj->{ident} }) {
    $log->error(sprintf('interface "%s" already exists', $obj->{ident}));
    $error++;
  }

  return if $error > 0;

  $GZ_REG{ $obj->{ident} } = $obj;

  # append trailing slash if not present
  $obj->{api_base} .= '/' unless substr($obj->{api_base}, length($obj->{api_base}) - 1, 1) eq '/';

  # confirmed settings are OK, load supporting modules and configure
  $obj->{ua} = new LWP::UserAgent;
  $obj->{ua}->cookie_jar(new HTTP::Cookies (file => $FindBin::Bin.'/../db/'.$obj->{cookie_jar}, autosave => 1));
  $obj->{ua}->agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0');
  $obj->{ua}->timeout(5);
  $obj->{ua}->add_handler("request_send",  sub { Log::Log4perl->get_logger('gazelle.ua.request')->debug(shift->dump); return });
  $obj->{ua}->add_handler("response_done", sub { Log::Log4perl->get_logger('gazelle.ua.response')->debug(shift->dump); return });

  $obj->{state} = GZ_NEW;

  return $obj;
}

sub login {
  my ($self)  = @_;
  my $log     = Log::Log4perl->get_logger('gazelle.intf.login');

  return 1 if $self->{state} == GZ_ALIVE; # already logged in

  $log->debug(sprintf('%s: attempting authentication as "%s"', $self->{ident}, $self->{username}));
  my $payload = $self->_api_post('login', username => $self->{username}, password => $self->{password});

  if ($payload->{status} eq 'failure') {
    $self->{state} = GZ_DEAD;
    $log->fatal(sprintf('%s: authentication failed', $self->{ident}));
    return;
  }

  $self->{state} = GZ_ALIVE; 
  $log->info(sprintf('%s: authentication succeeded', $self->{ident})); 
  return 1;
}

sub userstats_update {
  my ($self)  = @_;
  my $log = Log::Log4perl->get_logger('gazelle.api.userstats_update');
  my $payload = $self->_api_get('index') or return;

  $self->{bytes_up}   = $payload->{userstats}{uploaded};
  $self->{bytes_down} = $payload->{userstats}{downloaded};
  $self->{ratio}      = $payload->{userstats}{ratio};
  $self->{user_id}    = $payload->{userstats}{id};

  $log->info(sprintf('%s: %.2fGiB/%.2fGiB up/down (ratio: %.2f)', $payload->{username}, $self->{bytes_up} / 1073741824, $self->{bytes_down} / 1073741824, $self->{bytes_up} / $self->{bytes_down}));

  return 1;
}

# order_by order_way

sub torrent_search {
  my ($self, $match, %addl) = @_;
  my $payload = $self->_api_get('browse', 'searchstr' => $match, %addl) or return;

  return $payload->{results};
}

sub _api_get {
  my ($self, $action, %addl) = @_;
  my $log = Log::Log4perl->get_logger('gazelle.api.GET');
  $log->logconfess('API connection is not alive'), return unless $self->{state} == GZ_ALIVE;

  my $url = sprintf($self->{api_base}.'ajax.php?action=%s', $action);
  # manually prepare urlencoded keypairs 
  if (keys %addl) {
    $url .= '&'.join '&', map { uri_escape($_).'='.$addl{$_} } keys %addl;
  }

  $log->debug('requesting '.$url);

  my $res = $self->{ua}->get($url);
  $log->logconfess($res->status_line) unless $res->is_success;

  my $payload = decode_json($res->decoded_content);
  $log->debug(Dumper $payload) if $log->is_debug;

  return $payload->{response};
}

sub _api_post {
  my ($self, $action, %addl) = @_;
  my $log = Log::Log4perl->get_logger('gazelle.api.POST');
  $log->logconfess('API connection is not alive'), return unless ($action eq 'login' || $self->{state} == GZ_ALIVE);

  my $url  = $self->{api_base};
     $url .= ($action eq 'login' ? 'login.php?nowarn=%s' : 'ajax.php?action=%s'); # sprintf complains if no format 

  $log->debug("requesting $url with payload ".Dumper \%addl) if $log->is_debug;

  my $res = $self->{ua}->post(sprintf($url, $action), \%addl);

  # login special case, 200 = fail / 30x = success
  if ($action eq 'login') {
    return { status => 'success' } if $res->is_redirect;
    return { status => 'failure' };
  }

  $log->logconfess($res->status_line) unless $res->is_success;

  my $payload = decode_json($res->decoded_content);
  $log->debug(Dumper $payload) if $log->is_debug;

  return $payload->{response};
}

1;

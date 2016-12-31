package Transmission;

use v5.016;
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Log::Log4perl ':no_extra_logdie_message';
use JSON::RPC::Legacy::Client;
use JSON 'decode_json';
use Data::Dumper;

use constant {
  TM_DEAD  => 0, # interface became inactive, login expired / etc
  TM_NEW   => 1, # interface not yet logged in
  TM_ALIVE => 2, # interface logged in successfully / ready
};

our $VERSION = '1.0.0';
our %TM_REG; # to track unique instances

sub new {
  my ($class, %args) = @_;
  my $log            = Log::Log4perl->get_logger('transmission.intf.new');
  my $obj            = bless { }, $class;
  my $error          = 0;

  foreach my $key (qw[ident hostname port username password]) {
    unless (defined $args{$key}) {
      $log->error(sprintf('attempted to instantiate transmission interface "%s" without mandatory key "%s"', ($args{ident} // 'unknown'), $key));
      $error++;
    }
    $obj->{$key} = $args{$key};
  }

  if (defined $TM_REG{ $obj->{ident} }) {
    $log->error(sprintf('interface "%s" already exists', $obj->{ident}));
    $error++;
  }

  return if $error > 0;

  $TM_REG{ $obj->{ident} } = $obj;

  $obj->{ua} = new JSON::RPC::Legacy::Client;
  $obj->{ua}->ua->credentials(sprintf('%s:%d', $obj->{hostname}, $obj->{port}), 'Transmission', $obj->{username}, $obj->{password});
  $obj->{rpc} = sprintf('http://%s:%d/transmission/rpc', $obj->{hostname}, $obj->{port});

  $obj->{state} = TM_NEW;

  return $obj;
}

sub login {
  my ($self)  = @_;
  my $log     = Log::Log4perl->get_logger('transmission.intf.login');

  return 1 if $self->{state} == TM_ALIVE; # already logged in

  $log->debug(sprintf('%s: attempting authentication as "%s"', $self->{ident}, $self->{username}));

  # we have to manually make the request here as the ua object won't store the content if call() fails
  my $payload = $self->{ua}->ua->get($self->{rpc})->content;

  if ($payload =~ m!401: Unauthorized!) {
    $self->{state} = TM_DEAD;
    $log->fatal(sprintf('%s: authentication failed', $self->{ident}));
    return;
  }
  elsif ($payload =~ m!409: Conflict!) { # success - obtain session id
    ($self->{sid}) = ($payload =~ m!<code>X-Transmission-Session-Id: (.+)</code>!);
    $log->debug(sprintf('%s: sid %s', $self->{ident}, $self->{sid}));

    $self->{ua}->ua->default_header('X-Transmission-Session-Id' => $self->{sid});

    $self->{state} = TM_ALIVE;
    $log->info(sprintf('%s: authentication succeeded', $self->{ident}));
    return 1;
  }

  $log->fatal(sprintf('%s: unknown response from rpc: %s', $self->{ident}, $self->{ua}->status_line));
  return; 
}

sub torrent_list {
  my ($self)  = @_;
  my $log     = Log::Log4perl->get_logger('transmission.api.torrent_list');
  my $payload = $self->_rpc_call('torrent-get', { fields => [qw[id name]] }) or return;

  $log->debug(Dumper $payload);

  return 1;
}

sub _rpc_call {
  my ($self, $method, $args) = @_;
  my $log                    = Log::Log4perl->get_logger('transmission.rpc');
  $log->logconfess('RPC connection is not alive'), return unless $self->{state} == TM_ALIVE;

  my $res = $self->{ua}->call($self->{rpc}, { method => $method, arguments => $args });
  if ($res) {
    if ($res->is_error) {
      $log->logconfess(sprintf('%s: error while invoking rpc method "%s": %s', $self->{ident}, $method, $res->error_message));
      return;
    }
    else {
      return $res->content;
    }
  }
  else {
    # invalid session id. only re-issue request if we didn't call ourselves (limit recursion to single level)
    if ($self->{ua}->status_line eq '409 Conflict' && (caller 1)[3] ne 'Transmission::_rpc_call') {
      $log->debug('session id expired, re-negotiating session');
      $self->{state} = TM_NEW;

      unless ($self->login) {
        $log->fatal(sprintf('%s: session re-negotiation failed', $self->{ident}));
        return;
      }

      # re-execute the rpc request
      return $self->_rpc_call($method, $args);
    }

    $log->logconfess(sprintf('%s: failed to invoke rpc method "%s": %s', $self->{ident}, $method, $self->{ua}->status_line));
    return;
  }
}

1;

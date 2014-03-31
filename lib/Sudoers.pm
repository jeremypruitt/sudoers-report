#!/bin/env perl

package Sudoers;

our $VERSION = 'v0.0.3';

use utf8;
use strict;
use warnings;
use YAML::Tiny 'Dump';
use Hash::Merge 'merge';
use English qw( -no_match_vars );
use Getopt::Long;
use Pod::Usage qw( pod2usage );

Hash::Merge::set_behavior( 'RETAINMENT_PRECEDENT' );

my $DEBUG = 0;

sub trim {
    (my $s = $_[0]) =~ s/^\s+|\s+$//g;
    return $s;        
}

sub process_sudo_spec {
  my ($line,$spec) = @_;
  $line = trim($line);

  $line =~ /\s*(\S+)\s+\S+\s*=\s*.+/;
  my $user = $1;
  foreach my $foo ($line =~ m/\S+\s*=\s*(?:\(\S+\) NOPASSWD: )?(?:NOPASSWD: )?[^:]+[$:]?/g) {
    $foo =~ /\s*(\S+)\s*=\s*(.+)\s*(?::|$)/;
    my $host = $1;
    my $cmnd = $2;
    $spec->{$user}->{$host}->{'Cmnd_Alias'}->{$cmnd} = '1';
  }

  return $spec;
}

sub process_sudo_alias {
  my ($line,$alias) = @_;
  $line = trim($line);
  my ($name,$raw_value) = split(/\s*=\s*/,$line,2);
  my @values = split(/\s*,\s*/,$raw_value);
  $alias->{$name} = \@values;
  return $alias;
}

sub process_line {
  my ($line,$sudoers) = @_;

  chomp($line);

  if ($line =~ s/^\s*Host_Alias\s+//) {
    $sudoers->{'Host_Alias'} = process_sudo_alias($line,$sudoers->{'Host_Alias'});
  } elsif ($line =~ s/^\s*User_Alias\s+//) {
    $sudoers->{'User_Alias'} = process_sudo_alias($line,$sudoers->{'User_Alias'});
  } elsif ($line =~ s/^\s*Cmnd_Alias\s+//) {
    $sudoers->{'Cmnd_Alias'} = process_sudo_alias($line,$sudoers->{'Cmnd_Alias'});
  } elsif ($line =~ s/^\s*Runas_Alias\s+//) {
    $sudoers->{'Runas_Alias'} = process_sudo_alias($line,$sudoers->{'Runas_Alias'});
  } elsif ($line =~ /^\s*\S+\s+\S+\s*=\s*\S+/) {
    $sudoers->{'Spec'} = process_sudo_spec($line,$sudoers->{'Spec'});
  } else {
    print "UNKNOWN LINE: ${line}\n" if $DEBUG;
  }

  return $sudoers
}

sub combine_backslash_newlines {
    my ($line,$fh) = @_;
    if ($line =~ s/\\\s*$//) {
        $line .= <$fh>;
        $line =~ s/\s+/ /g;
       ($line, $fh) = combine_backslash_newlines($line,$fh);
    }
    return ($line, $fh);
}

sub build_sudoers_hash_from_file {
  my ($sudoers_file) = @_; 

  open(my $sudoers_fh, '<', $sudoers_file) or die "Could not open '$sudoers_file' $!\n";
 
  my $sudoers;

  while (my $line = <$sudoers_fh>) {
    next unless $line;
    next if $line =~ /^\s*(#|$)/;

    if ($line =~ /\\\s*$/) {
      ($line, $sudoers_fh) = combine_backslash_newlines($line,$sudoers_fh);
    }

    $sudoers = process_line($line,$sudoers);
  }

  return $sudoers;
}

sub process_host_alias{
  my ($host_alias,$spec_ref) = @_;

  my $report;
  my %spec = %{ $spec_ref };

  foreach my $user_alias ( keys(%$spec_ref) ) {
    if ($spec{$user_alias}{$host_alias}) {
      my %cmnd_alias_tuple = %{ $spec{$user_alias}{$host_alias}{'Cmnd_Alias'} };
      my @cmnd_alias = keys(%cmnd_alias_tuple);
      $report->{$user_alias} = $cmnd_alias[0];
    }
  }
  return $report;
}

sub query_hostname {
  my ($hostname,$sudoers) = @_;

  my $result;
  my @results;
  my %spec = %{ $sudoers->{'Spec'} };

  my @host_aliases;
  if ($hostname eq 'ALL') {
    push(@host_aliases,'ALL');
  } else {
    @host_aliases = @{ get_host_alias_names_for_hostname($hostname,$sudoers) };
  }

  foreach my $host_alias_name (@host_aliases) {
    my $processed_host_alias = process_host_alias($host_alias_name,$sudoers->{'Spec'});
    if ($processed_host_alias && $result) {
      $result = merge($processed_host_alias,$result);
    } elsif ($processed_host_alias) {
      $result = $processed_host_alias;
    }
  }

  return $result;
}

sub expand_user_alias {
  my ($username,$sudoers) = @_;
  my $foo;
  my $user_alias = $sudoers->{'User_Alias'}{$username};
  foreach my $username (@{$user_alias}) {
    if ($username =~ /^[A-Z0-9_]+$/) {
      $foo->{$username} = expand_user_alias($username,$sudoers);
    } else {
      $foo->{$username} = undef;
    }
  }
  return $foo;
}

sub host_report {
  my ($hostname,$sudoers) = @_;
  my $relevant_user_aliases = { };

  my $user_specs = merge(query_hostname($hostname,$sudoers) || {},query_hostname('ALL',$sudoers) || {});
  my @user_alias_names = keys(%{$user_specs});

  foreach my $user_alias_name (@user_alias_names) {
    my $user_alias_name_ref = $sudoers->{'User_Alias'}{$user_alias_name};
    next unless defined $user_alias_name_ref;
    my @user_aliases = @{ $user_alias_name_ref };

    # Convert array into seen hash
    my %user_alias;
    @user_alias{@user_aliases} = () x @user_aliases;
    $relevant_user_aliases->{$user_alias_name} = \%user_alias;

    # Loop over usernames...
    foreach my $username (@user_aliases) {
      # ...and expand as a user alias if the username is upcase.
      if ($username =~ /^[A-Z0-9_]+$/) {
        $relevant_user_aliases->{$user_alias_name}->{$username} = expand_user_alias($username,$sudoers);
      }
    }
  }

  return {
    'User Specs'   => $user_specs,
    'User Aliases' => $relevant_user_aliases,
  };
}

sub get_host_alias_names_for_hostname {
  my ($hostname,$sudoers) = @_;
  my @found_host_aliases;

  $sudoers->{'Host_Alias'} ||= { 'ALL' => [''] };
  my %host_alias = %{ $sudoers->{'Host_Alias'} };

  foreach my $host_alias_name ( keys(%host_alias) ) {
    my @host_aliases = @{ $host_alias{$host_alias_name} };
    my $host_aliases_string = join(',',@host_aliases);
    if (grep {$_ eq $hostname} @host_aliases) {
      push(@found_host_aliases, $host_alias_name);
    }
  }

  return \@found_host_aliases;
}

sub main {
    my ($self) = @_;
    my ($filename,$hostname);

    my $parser = Getopt::Long::Parser->new();
    $parser->configure( 'bundling', 'no_ignore_case', );

    my $cli_options = {
        'H|help|?' => sub { pod2usage( -verbose => 1 ) },
        'man'      => sub { pod2usage( -verbose => 2 ) },
        'usage'    => sub { pod2usage( -verbose => 0 ) },
        'version'  => sub { print "version: $VERSION\n"; exit 1; },
        'f|filename=s' => \$filename,
        'h|hostname=s' => \$hostname,
    };

    $parser->getoptions( %{$cli_options} ) or die "Incorrect usage.\n";
    if(!defined($hostname)){ pod2usage(-verbose => 0) }
    if(!defined($filename)){ pod2usage(-verbose => 0) }

    my $sudoers = build_sudoers_hash_from_file($filename);
    print Dump host_report($hostname,$sudoers);
    return;
}

__PACKAGE__->main() unless caller;

1;

__END__

#-----------------------------------------------------------------------------

=pod

=encoding utf8

=head1 NAME

C<sudoers-report> - Generates a report of the authorizations allowed for a
                    specific serverin a given sudoers file.

=head1 USAGE

sudoers-report --filename /etc/sudoers --hostname example

=head1 REQUIRED ARGUMENTS

=head1 ARGUMENTS

=head1 OPTIONS

These are the application options.

=over

=item B<-?, --help>

Displays a brief summary of options and exits.

=item B<--man>

Displays the complete manual and exits.

=item B<--usage>

Displays the basic application usage.

=item B<--version>

Displays the version number and exits.

=item B<--filename>

Accepts a path to the sudoers file

=item B<--hostname>

Accepts a hostname to report

=back

=head1 DESCRIPTION

This application can do < x, y, and z >.

=head1 DIAGNOSTICS

=head1 EXIT STATUS

0 - Sucessful program execution.
1 - Program exited normally. --help, --man, and --version return 1.
2 - Program exited normally. --usage returns 2.

=head1 CONFIGURATION

=head1 DEPENDENCIES

=head1 INCOMPATIBILITIES

=head1 BUGS AND LIMITATIONS

=head1 HOMEPAGE

http://www.github.com/juniper/sudoers-report

=head1 AUTHOR

Name <jpruitt@juniper.net>

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2012 Juniper Networks. All rights reserved.

=cut

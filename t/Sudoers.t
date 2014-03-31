#!/bin/env perl

use strict;
use warnings;
use Test::More 'no_plan';
use Hash::Merge 'merge';
use YAML::Tiny;

use lib './lib';

my $class = 'Sudoers';

##
## Use module and call 'main' subroutine
##
use_ok( $class );
can_ok( $class, 'main' );

##
## Process a Host_Alias
##
my $host_alias_string         = 'SERVERS=box1.example.com,box2.example.com';
my $expected_host_alias_tuple = { 'SERVERS' => [ 'box1.example.com', 'box2.example.com' ] };
my $actual_host_alias_tuple   = Sudoers::process_sudo_alias($host_alias_string,{ });
is_deeply($actual_host_alias_tuple, $expected_host_alias_tuple, 'Processed Host_Alias string');

##
## Process a Host_Alias Line
##
my $host_alias_line       = 'Host_Alias    SERVERS=box1.example.com,box2.example.com';
my $expected_sudoers_hash = { 'Host_Alias' => { 'SERVERS' => [ 'box1.example.com', 'box2.example.com' ] } };
my $actual_sudoers_hash   = Sudoers::process_line($host_alias_line,{ });
is_deeply($actual_sudoers_hash, $expected_sudoers_hash, 'Processed Host_Alias line');

##
## Process a User_Alias
##
my $user_alias_string         = 'ADMINS=juser,toor';
my $expected_user_alias_tuple = { 'ADMINS' => [ 'juser', 'toor' ] };
my $actual_user_alias_tuple   = Sudoers::process_sudo_alias($user_alias_string,{ });
is_deeply($actual_user_alias_tuple, $expected_user_alias_tuple, 'Processed User_Alias string');

##
## Process a User_Alias Line
##
my $user_alias_line    = 'User_Alias    ADMINS=juser,toor';
my $expected_user_hash = { 'User_Alias' => { 'ADMINS' => [ 'juser', 'toor' ] } };
my $actual_user_hash   = Sudoers::process_line($user_alias_line,{ });
is_deeply($actual_user_hash, $expected_user_hash, 'Processed User_Alias line');

##
## Process a Sudo Spec #1
##
# Spec: %test13   WORKSTATIONS=(ALL) ALL
# Spec: SUSADMINS sustaining-eng=(ALL) ALL
my $sudo_spec_line1     = 'ADMINS      SERVERS=(ALL) ALL';
my $expected_sudo_spec1 = {
  'ADMINS' => {
    'SERVERS' => {
      'Cmnd_Alias' => { '(ALL) ALL' => '1' },
    },
  },
};
my $actual_sudo_spec1 = Sudoers::process_sudo_spec($sudo_spec_line1,{ });
is_deeply($actual_sudo_spec1, $expected_sudo_spec1, 'Processed Sudo Spec line: User_Alias (ALL) ALL');

##
## Process a Sudo Spec #2
##
# Spec: %test13   WORKSTATIONS=(ALL) ALL
# Spec: SUSADMINS sustaining-eng=(ALL) ALL
my $sudo_spec_line2     = '%test   WORKSTATIONS=(ALL) ALL';
my $expected_sudo_spec2 = {
  '%test' => {
    'WORKSTATIONS' => {
      'Cmnd_Alias' => { '(ALL) ALL' => '1' },
    },
  },
};
my $actual_sudo_spec2 = Sudoers::process_sudo_spec($sudo_spec_line2,{ });
is_deeply($actual_sudo_spec2, $expected_sudo_spec2, 'Processed Sudo Spec line: Unix Group (ALL) ALL');

my $sudoers = Sudoers::build_sudoers_hash_from_file('./sudoers.example');

##
## get_host_alias_names_for_hostname
##
my $hostname = 'desktop2';
my @expected_host_aliases = [
  'ENGINEERING',
  'WORKSTATIONS',
];
my $actual_host_aliases = Sudoers::get_host_alias_names_for_hostname($hostname,$sudoers);
can_ok( $class, 'main' );
is_deeply($actual_host_aliases, @expected_host_aliases, "Got host aliases for $hostname")
  or diag explain $actual_host_aliases;

##
## What if a Host Alias doesn't exist?
##
my $sudoers_without_host_alias = Sudoers::build_sudoers_hash_from_file('./sudoers.example_without_host_alias');
Sudoers::get_host_alias_names_for_hostname($hostname,$sudoers_without_host_alias);


##
## process_host_report for host alias
##
my $host_alias = 'WORKSTATIONS';
my $expected_host_alias_result = {
  '%root' => '(ALL) ALL',
  '%wheel' => '(ALL) ALL',
  'ADMINS' => '(ALL) ALL',
  'BACKUP_ADMINS' => '(ALL) /bin/backup',
};
my $actual_host_alias_result = Sudoers::process_host_alias($host_alias,$sudoers->{'Spec'});
is_deeply($actual_host_alias_result, $expected_host_alias_result, "Got host report for host alias: $host_alias")
  or diag explain $actual_host_alias_result;

##
## host_report_for hostname
##
$hostname = 'desktop2';
my $expected_query_result = {
  'root'  => '(ALL) ALL',
  '%root' => '(ALL) ALL',
  '%wheel' => '(ALL) ALL',
  'ADMINS' => [
    '(ALL) ALL',
    '(ALL) /bin/ls',
  ],
  'BACKUP_ADMINS' => [
    '(ALL) /bin/backup',
    '(ALL) /bin/backup',
  ],
};
my $actual_query_hostname_result = Sudoers::query_hostname($hostname,$sudoers);
my $actual_query_all_result = Sudoers::query_hostname('ALL',$sudoers);
my $actual_query_result = merge($actual_query_all_result,$actual_query_hostname_result);
is_deeply(
  $actual_query_result,
  $expected_query_result,
  "Got host report for hostname: $hostname"
) or diag explain $actual_query_result;

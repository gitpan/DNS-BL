package DNS::BL::cmds::connect::db;

use DNS::BL;

use 5.006001;
use strict;
use warnings;
use Fcntl qw(:DEFAULT);

use MLDBM qw(DB_File Storable);

use vars qw/@ISA/;

@ISA = qw/DNS::BL::cmds/;

use Carp;

our $VERSION = '0.00_01';
$VERSION = eval $VERSION;  # see L<perlmodstyle>

# Preloaded methods go here.

=pod

=head1 NAME

DNS::BL::cmds::connect::db - Implement the DB connect command for DNS::BL

=head1 SYNOPSIS

  use DNS::BL::cmds::connect::db;

=head1 DESCRIPTION

This module implements the connection to a DB backend where C<DNS::BL>
data will be stored. On each call to this class' methods, a hash will
be C<tie()>d and then C<untie()>d. This guarantees that the underlying
DB structure will be unlocked and available for other commands that
may, for instance, replace or manipulate the hash "from under us".

The following methods are implemented by this module:

=over

=item C<-E<gt>execute()>

See L<DNS::BL::cmds> for information on this method's purpose.

The connect command follows a syntax such as

  connect db <args> ...

Note that the 'connect' token must be removed by the calling class,
usually C<DNS::BL::cmds::connect>. B<args> are key - value pairs
specifying different parameters as described below. Unknown parameters
are reported as errors. The complete calling sequence is as

  connect db file "filename"

Where "filename" refers to the DB file where data is to be found. If
the file does not exist, it will be created (provided that permissions
allow).

This class will be C<use>d and then, its C<execute()> method invoked
following the same protocol outlined in L<DNS::BL>. Prior C<connect()>
information is to be removed by the calling class.

=cut

sub execute 
{ 
    my $bl	= shift;
    my $command	= shift;	# Expect "db"
    my %args	= @_;

    my @known 	= qw/file/;

    unless ($command eq 'db')
    {
	return wantarray ? 
	    (&DNS::BL::DNSBL_ESYNTAX(), 
	     "'" . __PACKAGE__ . "' invoked by connect type '$command'")
	    : &DNS::BL::DNSBL_ESYNTAX();
    }

    for my $k (keys %args)
    {
	unless (grep { $k eq $_ } @known)
	{
	    return wantarray ? (&DNS::BL::DNSBL_ESYNTAX(), 
				"Unknown argument '$k' to 'connect db'")
		: &DNS::BL::DNSBL_ESYNTAX();
	}
    }

    unless (exists $args{file} and length($args{file}))
    {
	return wantarray ? (&DNS::BL::DNSBL_ESYNTAX(), 
			    "Missing file name for 'connect db'")
	    : &DNS::BL::DNSBL_ESYNTAX();
    }

    # Store the passed data

    $args{_class} = __PACKAGE__;

    $bl->set("_connect", \%args);

    # Add I/O methods to the $bl object so that further calls can be
    # processed

    $bl->set("_read",	\&_read);
    $bl->set("_match",	\&_match);
    $bl->set("_write",	\&_write);
    $bl->set("_erase",	\&_delete);
    $bl->set("_commit",	\&_commit);
    
    return wantarray ? (&DNS::BL::DNSBL_OK, "Connected to DB") : 
	&DNS::BL::DNSBL_OK;
};

sub _portal
{
    my $bl	= shift;	# Calling BL object
    my $r	= shift;	# Ref to a hash to be tied
    my $data	= $bl->get('_connect');

    unless ($data or $data->{_class} eq __PACKAGE__)
    {
	return wantarray ? 
	    (&DNS::BL::DNSBL_ESYNTAX(), 
	     "->write can only be called while 'connect db' is in effect")
	    : &DNS::BL::DNSBL_ESYNTAX();
    }

    unless (tie %$r, 'MLDBM', $data->{file}, O_CREAT|O_RDWR, 0640)
    {
	return wantarray ? 
	    (&DNS::BL::DNSBL_ECONNECT(), 
	     "Cannot tie to file '" . $data->{file} . "'")
	    : &DNS::BL::DNSBL_ECONNECT();
    }

    return wantarray ? (&DNS::BL::DNSBL_OK, "DB tied") : 
	&DNS::BL::DNSBL_OK;
}

sub _write
{
    my $bl	= shift;
    my $e	= shift;

    my %db	= ();
    my @r = _portal($bl, \%db);
    return wantarray ? @r : $r[0] if $r[0] != &DNS::BL::DNSBL_OK;

    $db{$e->addr->network->cidr} = $e;

    return wantarray ? (&DNS::BL::DNSBL_OK, "OK - Done") : 
	&DNS::BL::DNSBL_OK;
}

sub _read
{
    my $bl	= shift;
    my $e	= shift;

    my %db	= ();
    my @r = _portal($bl, \%db);
    return wantarray ? @r : $r[0] if $r[0] != &DNS::BL::DNSBL_OK;

    my $N = $e->addr;
    my @ret = ();

    for my $n (keys %db)
    {
	my $ip = new NetAddr::IP $n;
	next unless $ip;
	push @ret, $db{$n} if $N->contains($ip);
    }

    return (&DNS::BL::DNSBL_OK, scalar @ret . " entries found",
	    @ret) if @ret;
    return (&DNS::BL::DNSBL_ENOTFOUND, "No entries matched");
}

sub _match
{
    my $bl	= shift;
    my $e	= shift;

    my %db	= ();
    my @r = _portal($bl, \%db);
    return wantarray ? @r : $r[0] if $r[0] != &DNS::BL::DNSBL_OK;

    my $N = $e->addr;
    my @ret = ();

    for my $n (keys %db)
    {
	my $ip = new NetAddr::IP $n;
	next unless $ip;
	push @ret, $db{$n} if $N->within($ip);
    }

    return (&DNS::BL::DNSBL_OK, scalar @ret . " entries found",
	    @ret) if @ret;
    return (&DNS::BL::DNSBL_ENOTFOUND, "No entries matched");
}

sub _commit
{
    return wantarray ? (&DNS::BL::DNSBL_OK, "commit is not required with DB") 
	: &DNS::BL::DNSBL_OK;
}

sub _delete
{
    my $bl	= shift;
    my $e	= shift;

    my %db	= ();
    my @r = _portal($bl, \%db);
    return wantarray ? @r : $r[0] if $r[0] != &DNS::BL::DNSBL_OK;

    my $N = $e->addr;
    my $num = 0;

    for my $n (keys %db)
    {
	my $ip = new NetAddr::IP $n;
	next unless $ip;
	next unless $N->contains($ip);
	delete $db{$n};
	++$num;
    }

    if ($num)
    {
	return (&DNS::BL::DNSBL_OK, "$num entries deleted");
    }
    else
    {
	return (&DNS::BL::DNSBL_ENOTFOUND, "No entries deleted");
    }
}

sub DNS::BL::cmds::_db_dump::execute
{
    my $bl	= shift;
    my %db	= ();

    my $data	= $bl->get('_connect');

    unless ($data or $data->{_class} eq __PACKAGE__)
    {
	return wantarray ? 
	    (&DNS::BL::DNSBL_ESYNTAX(), 
	     "'db_dump' can only be called while 'connect db' is in effect")
	    : &DNS::BL::DNSBL_ESYNTAX();
    }

    unless (tie %db, 'MLDBM', $data->{file}, O_RDONLY, 0640)
    {
	return wantarray ? 
	    (&DNS::BL::DNSBL_ECONNECT(), 
	     "Cannot tie to file '" . $data->{file} . "'")
	    : &DNS::BL::DNSBL_ECONNECT();
    }

    print Data::Dumper->Dump([ \%db ]);

    untie %db;

    return wantarray ? (&DNS::BL::DNSBL_OK, "OK - Done") : 
	&DNS::BL::DNSBL_OK;
}

1;
__END__

=pod

=back

=head2 EXPORT

None by default.


=head1 HISTORY

$Log: db.pm,v $
Revision 1.2  2004/10/12 17:44:46  lem
Updated docs. Added print with format

Revision 1.1  2004/10/11 21:16:34  lem
Basic db and commands added


=head1 SEE ALSO

Perl(1), L<DNS::BL>.

=head1 AUTHOR

Luis Muñoz, E<lt>luismunoz@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Luis Muñoz

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut

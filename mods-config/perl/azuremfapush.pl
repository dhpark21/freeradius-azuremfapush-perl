use strict;
use warnings;
use HTTP::Tiny;

# https://wiki.freeradius.org/modules/Rlm_perl#logging is wrong...
use constant {
	L_AUTH  => 2,
	L_INFO  => 3,
	L_ERR   => 4,
	L_WARN  => 5,
	L_PROXY => 6,
	L_ACCT  => 7,
	L_DBG   => 16,
};

# https://wiki.freeradius.org/modules/Rlm_perl#return-codes
use constant {
	RLM_MODULE_REJECT   =>  0,	# immediately reject the request
	RLM_MODULE_FAIL     =>  1,	# module failed, don't reply
	RLM_MODULE_OK       =>  2,	# the module is OK, continue
	RLM_MODULE_HANDLED  =>  3,	# the module handled the request, so stop
	RLM_MODULE_INVALID  =>  4,	# the module considers the request invalid
	RLM_MODULE_USERLOCK =>  5,	# reject the request (user is locked out)
	RLM_MODULE_NOTFOUND =>  6,	# user not found
	RLM_MODULE_NOOP     =>  7,	# module succeeded without doing anything
	RLM_MODULE_UPDATED  =>  8,	# OK (pairs modified)
	RLM_MODULE_NUMCODES =>  9,	# How many return codes there are
};

use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_PERLCONF);

my $realm = $RAD_PERLCONF{'realm'};
my $tenant = $RAD_PERLCONF{'tenant'};
my $client_secret = $RAD_PERLCONF{'secret'};

my $client_id = "981f26a1-7f43-403b-a875-f8b09b8cd720";
my $scope = 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/.default';
my $grant_type = 'client_credentials';

my $token = "";
my $recurse_control = 0;

sub update_token {
	&radiusd::radlog(L_INFO, "aquire oauth2 token");
	my $http = HTTP::Tiny->new();
	my $res = $http->post_form( "https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token", {
		client_id => $client_id,
		client_secret => $client_secret,
		scope => $scope,
		grant_type => $grant_type
	} );
	die "Error: unhandled HTTP/$res->{status}" unless $res->{success};

	return $1 if $res->{content} =~ /{.*"access_token":"([^"]+)".*}/;
	die "Error: no token received\n $res->{content}";
}

sub authenticate {
	&radiusd::radlog(L_DBG, 'azure_mfa authenticate');

	my $user = $RAD_REQUEST{'User-Name'};
	if ( $user !~ /.*@.*$/ ){ $user .= "@" . $realm; }
	my $XML = <<"EOF";
<BeginTwoWayAuthenticationRequest>
 <Version>1.0</Version>
 <UserPrincipalName>$user</UserPrincipalName>
 <Lcid>en-us</Lcid>
 <AuthenticationMethodProperties xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
  <a:KeyValueOfstringstring>
   <a:Key>OverrideVoiceOtp</a:Key>
   <a:Value>false</a:Value>
  </a:KeyValueOfstringstring>
 </AuthenticationMethodProperties>
 <ContextId>eba037c8-2b18-4852-8548-f34b7c01fae6</ContextId>
 <SyncCall>true</SyncCall>
 <RequireUserMatch>true</RequireUserMatch>
 <CallerName>radius</CallerName>
 <CallerIP>UNKNOWN:</CallerIP>
</BeginTwoWayAuthenticationRequest>
EOF

	$token = update_token unless $token;

	my $res = { status => '' };
	my $http = HTTP::Tiny->new();
	do {
		$token = update_token if ( $res->{status} eq '401');
		&radiusd::radlog(L_INFO, "initiating mfa push");
		$res = $http->post( 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/BeginTwoWayAuthentication', {
				headers => {
					"Authorization" => "Bearer ${token}",
					"Content-Type" => "application/xml"
				},
				content => $XML
			} );
	} while ( $res->{status} eq '401' && $recurse_control++ <= 1 );
	$recurse_control = 0;

	unless ($res->{success}) {
		&radiusd::radlog(L_ERR, "unhandled HTTP/$res->{status}");
    	return RLM_MODULE_FAIL;
	}

	$res->{content} =~ m/<AuthenticationResult>(.*)<\/AuthenticationResult>/i;

	if ( lc($1) eq "true" ) {
			return RLM_MODULE_OK;
	}else{
		return RLM_MODULE_REJECT;
	}
}

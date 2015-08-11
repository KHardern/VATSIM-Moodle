<?php
/**
 * @author Kieran Hardern
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/auth/vatsim/SSO.class.php');
require_once($CFG->dirroot.'/auth/vatsim/OAuth.php');

class auth_plugin_vatsim extends auth_plugin_base {
    
    /**
     * Constructor.
     */
    function auth_plugin_vatsim() {
        $this->pluginname = 'VATSIM SSO';
        $this->authtype = 'vatsim';
        $this->roleauth = 'vatsim';
        $this->errorlogtag = '[AUTH VATSIM]';
    }
    
    /**
     * Prevent authenticate_user_login() to update the password in the DB
     * @return boolean
     */
    function prevent_local_passwords() {
        return true;
    }
    
    /**
     * Authenticates user against VATSIM
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $DB, $CFG;

        //retrieve the user matching username
        $user = $DB->get_record('user', array('username' => $username,
            'mnethostid' => $CFG->mnet_localhost_id));

        //username must exist
        if (!empty($user)) {
            return true;
        }

        return false;
    }
    
    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }
    
    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }
    
    function loginpage_hook(){
        
        global $CFG, $SESSION, $DB, $USER;
        
        require_once($CFG->dirroot.'/auth/vatsim/config.php');
        
        // initiate the SSO class with consumer details and encryption details
        $SSO = new SSO($sso['base'], $sso['key'], $sso['secret'], $sso['method'], $sso['cert']);
        
        // return variable is needed later in this script
        $sso_return = $sso['return'];
        // remove other config variables
        unset($sso);

        // if VATSIM has redirected the member back
        if (isset($_GET['oauth_verifier']) && !isset($_GET['oauth_cancel'])){
            // check to make sure there is a saved token for this user
            if (isset($_SESSION[SSO_SESSION]) && isset($_SESSION[SSO_SESSION]['key']) && isset($_SESSION[SSO_SESSION]['secret'])){

                if (@$_GET['oauth_token']!=$_SESSION[SSO_SESSION]['key']){
                    throw new moodle_exception("An error occurred with the login process - please try again", 'auth_vatsim');
                }

                if (@!isset($_GET['oauth_verifier'])){
                    throw new moodle_exception("An error occurred with the login process", 'auth_vatsim');
                }

                // obtain the details of this user from VATSIM
                $vatsimUser = $SSO->checkLogin($_SESSION[SSO_SESSION]['key'], $_SESSION[SSO_SESSION]['secret'], @$_GET['oauth_verifier']);

                if ($vatsimUser){
                    // One-time use of tokens, token no longer valid
                    unset($_SESSION[SSO_SESSION]);
                    $vatsim = $vatsimUser->user;
                    //print_r($user->user);
                    
                    $username = $vatsim->id;
                    
                    // plugin only designed where email address is returned, if no email specified, 
                    if (@empty($vatsim->email)) {
                        throw new moodle_exception('noemail', "auth_vatsim");
                    }
                    
                    $useremail = $vatsim->email;
                    
                    // find the user in the current database, by CID, not email
                    $user = $DB->get_record('user', array('username' => $username, 'deleted' => 0, 'mnethostid' => $CFG->mnet_localhost_id));

                    // create the user if it doesn't exist
                    if (empty($user)) {

                        // deny login if setting "Prevent account creation when authenticating" is on
                        if($CFG->authpreventaccountcreation) throw new moodle_exception("noaccountyet", "auth_vatsim");

                        //retrieve more information from the provider
                        $newuser = new stdClass();
                        $newuser->email = $useremail;
                        $newuser->firstname =  $vatsim->name_first;
                        $newuser->lastname =  $vatsim->name_last;
                        $newuser->country = $vatsim->country->code;

                        create_user_record($username, '', 'vatsim');

                    } else {
                        $username = $user->username;
                    }

                    
                    add_to_log(SITEID, 'auth_vatsim', '', '', $username . '/' . $useremail);

                    $user = authenticate_user_login($username, null);
                    if ($user) {
                        
                        //prefill more user information if new user
                        if (!empty($newuser)) {
                            $newuser->id = $user->id;
                            $DB->update_record('user', $newuser);
                            $user = (object) array_merge((array) $user, (array) $newuser);
                        }

                        complete_user_login($user);

                        // Redirection
                        if (user_not_fully_set_up($USER)) {
                            $urltogo = $CFG->wwwroot.'/user/edit.php';
                            // We don't delete $SESSION->wantsurl yet, so we get there later
                        } else if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                            $urltogo = $SESSION->wantsurl;    // Because it's an address in this site
                            unset($SESSION->wantsurl);
                        } else {
                            // No wantsurl stored or external - go to homepage
                            $urltogo = $CFG->wwwroot.'/';
                            unset($SESSION->wantsurl);
                        }
                        redirect($urltogo);
                    }
                } else {
                    // OAuth or cURL errors have occurred
                    //$error = $SSO->error();

                    throw new moodle_exception("An error occurred with the login process", 'auth_vatsim');
                }
            } 
        // the user cancelled their login and were sent back
        } else if (isset($_GET['oauth_cancel'])){
            throw new moodle_exception("You cancelled your login", 'auth_vatsim');
        }

        // create a request token for this login. Provides return URL and suspended/inactive settings
        $token = $SSO->requestToken($sso_return, false, false);

        if ($token){

            // store the token information in the session so that we can retrieve it when the user returns
            $_SESSION[SSO_SESSION] = array(
                'key' => (string)$token->token->oauth_token, // identifying string for this token
                'secret' => (string)$token->token->oauth_token_secret // secret (password) for this token. Keep server-side, do not make visible to the user
            );

            // redirect the member to VATSIM
            $SSO->sendToVatsim();

        } else {

            throw new moodle_exception("An error occurred with the login process", 'auth_vatsim');

        }

        
    }
    
    /**
     * Called when the user record is updated.
     *
     * We check there is no hack-attempt by a user to change his/her email address
     *
     * @param mixed $olduser     Userobject before modifications    (without system magic quotes)
     * @param mixed $newuser     Userobject new modified userobject (without system magic quotes)
     * @return boolean result
     *
     */
    function user_update($olduser, $newuser) {
        if ($olduser->email != $newuser->email) {
            return false;
        } else {
            return true;
        }
    }
    
}

?>

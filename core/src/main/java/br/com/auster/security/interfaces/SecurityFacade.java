/*
 * Copyright (c) 2004 Auster Solutions. All Rights Reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Created on 10/04/2006
 */
package br.com.auster.security.interfaces;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import br.com.auster.persistence.FetchCriteria;
import br.com.auster.security.base.SecurityException;
import br.com.auster.security.model.Domain;
import br.com.auster.security.model.PasswordInfo;
import br.com.auster.security.model.Role;
import br.com.auster.security.model.User;


/**
 * @author framos
 * @version $Id$
 */
public interface SecurityFacade {

	// TODO javadoc all API calls
	
	// user-related APIs
    public void createUser(User _user, PasswordInfo _password) throws SecurityException;
    public boolean alterUser(User _user) throws SecurityException;
    public boolean lockUser(String _loginName, String _adminLogin) throws SecurityException;
    public boolean unlockUser(String _loginName, String _adminLogin) throws SecurityException;
    public User loadUser(String _loginName) throws SecurityException;
    public User loadUser(long _uid) throws SecurityException;
    public Collection loadUsers() throws SecurityException;
    public Collection loadUsers(FetchCriteria _fetch) throws SecurityException;
    public int countUsers() throws SecurityException;
    public User loadUserDetails(String loginName) throws SecurityException;
    public String parseUserRemoteLogin(String userLogin);
    
    // password-related APIs
    public boolean assignPassword(String _loginName, PasswordInfo _password, String _admin) throws SecurityException;
    public boolean assignPassword(String _loginName, PasswordInfo _password, String _admin, int maxStoredPasswords) throws SecurityException;
    public boolean validateCurrentPassword(String _loginName, String _typePassword) throws SecurityException;
    public Collection loadPasswordHistory(String _loginName) throws SecurityException;
    public Collection loadPasswordHistory(String _loginName, FetchCriteria _fetch) throws SecurityException;

    // role-related APIs
    public void createRole(Role _role) throws SecurityException;
    public boolean alterRole(Role _role) throws SecurityException;
	public boolean removeRole(String _name, String _newRole) throws SecurityException;
  	public Role loadRole(String _name) throws SecurityException;
	public Collection loadRoles() throws SecurityException;
	public Collection loadRoles(FetchCriteria _fetch) throws SecurityException;
	public Collection loadRootRoles() throws SecurityException;
	public Collection loadRootRoles(FetchCriteria _fetch) throws SecurityException;
	public Collection loadRoles(int _levels) throws SecurityException;
	public Collection loadRoles(int _levels, FetchCriteria _fetch) throws SecurityException;
	public int countRoles() throws SecurityException;
	
    // user-role permissions APIs   
    public boolean grantRole(String _loginName, String _role)  throws SecurityException;
    public boolean grantRole(String _loginName, String _role, Date _from, Date _until)  throws SecurityException;
    public boolean revokeRole(String _loginName, String  _role)  throws SecurityException;
    public Collection loadActiveRoles(String _loginName)  throws SecurityException;
    
    //domain-related APIs
    public void createDomain(Domain _domain) throws SecurityException;
    public boolean alterDomain(Domain _domain) throws SecurityException;
    public boolean removeDomain(String _domainName) throws SecurityException;
    public Domain loadDomain(String _domainName) throws SecurityException;
    public Collection loadDomains() throws SecurityException;
    public Collection loadDomains(FetchCriteria _fetch) throws SecurityException;
    public int countDomains() throws SecurityException;
    
    // role-domain permissions APIs   
    public boolean grantDomain(String _domainName, String _roleName)  throws SecurityException;
    public boolean grantDomain(String _domainName, String _roleName, Date _from, Date _until)  throws SecurityException;
    public boolean revokeDomain(String _domainName, String _roleName)  throws SecurityException;
    public Collection loadPermittedRoles(String _domainName)  throws SecurityException;
    public Collection loadActiveDomains(String _roleName) throws SecurityException;
    public Collection loadActiveUserDomains(String loginName) throws SecurityException;
    public Collection loadActiveUserRoles(String loginName) throws SecurityException;
    // authentication & authorization APIs
    public boolean authorize(String _loginName, String _domainName)throws SecurityException;
    public boolean authenticate(String _loginName, String password) throws SecurityException;
    
    // security policy
    public void setPolicies(SecurityPolicy _policy);
    
    // USER BY ROLE
    public List userByRole(String role, String userEvent) throws SecurityException;
}

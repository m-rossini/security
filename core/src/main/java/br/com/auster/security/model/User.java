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
package br.com.auster.security.model;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import br.com.auster.om.reference.CustomizableEntity;


/**
 * @author framos
 * @version $Id$
 */
public class User extends CustomizableEntity implements Serializable, Comparable {

 
	protected String firstName;
    protected String lastName;
    protected String email;    
    protected String login;
    protected boolean locked;
    protected List passwords;
    protected Set userRoles;
    protected Set allowedDomains;

    
    
    public User() {
    	this(0);
    }
    
    public User(long _uid) {
    	super(_uid);
    	this.passwords = new LinkedList();
    	this.allowedDomains = new TreeSet();
    	this.userRoles = new TreeSet();
    }
    
    
    public final String getEmail() {
        return this.email;
    }
    
    public final void setEmail(String _email) {
        this.email = _email;
    }

    public final String getLogin() {
        return this.login;
    }
    
    public final void setLogin(String _login) {
        this.login = _login;
    }
    
    public final String getFirstName() {
        return this.firstName;
    }
    
    public final void setFirstName(String _name) {
        this.firstName = _name;
    }

    public final String getLastName() {
        return this.lastName;
    }
    
    public final void setLastName(String _name) {
        this.lastName = _name;
    }
        
    public final boolean isLocked() {
        return this.locked;
    }
    
    public final void setLocked(boolean _locked) {
        this.locked = _locked;
    }
     
    public String getFullName() {
    	return (this.getFirstName() == null ? "" : this.getFirstName()) + " " + 
    		   (this.getLastName() == null  ? "" : this.getLastName() );
    }

    public String getFormalName() {
    	return (this.getLastName() == null  ? "" : this.getLastName() ) + ", " + 
		       (this.getFirstName() == null ? "" : this.getFirstName());
    }
    
    public void setRoles(Set _roles) {
    	this.userRoles = _roles;
    }
    
    public Set getRoles() {
    	return (this.userRoles == null ? Collections.EMPTY_SET : this.userRoles);
    }

    public void setAllowedDomains(Set _domains) {
    	this.allowedDomains = _domains;
    }
    
    public Set getAllowedDomains() {
    	return this.allowedDomains;
    }
    
    
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return 
        "BaseUser : [" +
        "email=" + this.getEmail() + ";" +
        "firstName=" + this.getFirstName() + ";" +
        "lastName=" + this.getLastName() + ";" +
        "locked?=" + this.isLocked() + ";" +
        "loginName=" + this.getLogin() + ";" +
        "]";
    }
    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object _otherUser) {
        return (this.compareTo(_otherUser)==0);
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return (37 + 37*this.getLogin().hashCode()); 
    }
    
    /**
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(Object _otherUser) {
        User otherUser = (User)_otherUser;
        return this.getLogin().compareTo(otherUser.getLogin());
    }

}

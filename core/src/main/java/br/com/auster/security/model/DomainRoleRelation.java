/*
 * Copyright (c) 2004-2006 Auster Solutions. All Rights Reserved.
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
 * Created on 29/09/2006
 */
package br.com.auster.security.model;

import java.io.Serializable;
import java.sql.Timestamp;

import br.com.auster.om.reference.CustomizableEntity;

/**
 * @author framos
 * @version $Id$
 */
public class DomainRoleRelation extends CustomizableEntity implements Serializable, Comparable {

	
	
	protected long domainUid;
	protected String domainName;
	protected long roleUid;
	protected String roleName;
	protected Timestamp assignDate;
	protected Timestamp expirationDate;
	
	
	
	public DomainRoleRelation(long _userUid, long _roleUid) {
		this.setDomainUid(_userUid);
		this.setRoleUid(_roleUid);
	}

	public final Timestamp getAssignDate() {
		return assignDate;
	}
	public final void setAssignDate(Timestamp assignDate) {
		this.assignDate = assignDate;
	}
	
	public final Timestamp getExpirationDate() {
		return expirationDate;
	}
	public final void setExpirationDate(Timestamp expirationDate) {
		this.expirationDate = expirationDate;
	}
	
	public final long getRoleUid() {
		return roleUid;
	}
	protected final void setRoleUid(long roleUid) {
		this.roleUid = roleUid;
	}
	
	public final long getDomainUid() {
		return domainUid;
	}
	protected final void setDomainUid(long userUid) {
		this.domainUid = userUid;
	}
	
	public final String getDomainName() {
		return this.domainName;
	}
	public final void setDomainName(String _name) {
		this.domainName = _name;
	}
	
	public final String getRoleName() {
		return this.roleName;
	}
	public final void setRoleName(String _name) {
		this.roleName = _name;
	}
	
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return 
        "UserRoleRelation : [" +
        "domainId=" + this.getDomainUid() + ";" +
        "roleId=" + this.getRoleUid() + ";" +
        "assignDate=" + this.getAssignDate() + ";" +
        "expirationAt=" + this.getExpirationDate() + ";" +
        "]";
    }
    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object _otherRelation) {
        return (this.compareTo(_otherRelation)==0);
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        int result = (int) (17 + 37*this.getDomainUid());
        result += 37*this.getRoleUid();
        return result;
    }
    
    /**
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(Object _otherRelation) {
    	DomainRoleRelation otherRelation = (DomainRoleRelation)_otherRelation;
    	if (otherRelation.getDomainUid() == this.getDomainUid()) {
    		return (int)(this.getRoleUid() - otherRelation.getRoleUid());
    	}
    	return (int) (this.getDomainUid() - otherRelation.getDomainUid());
    }	
}

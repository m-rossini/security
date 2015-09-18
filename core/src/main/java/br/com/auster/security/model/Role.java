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

import br.com.auster.om.reference.CustomizableEntity;


/**
 * @author framos
 * @version $Id$
 */
public class Role extends CustomizableEntity implements Serializable, Comparable {

    

	
	protected static final int CARDINALITY_UNDEFINED = -1;

	protected static final int MAX_DESCRIPTION_TOSTRING = 100;
    
    
    protected String name;
    protected String description;
    protected int cardinality;
    protected boolean active;
    
    
    
    public Role(String _name) {
        this.setRoleName(_name);
        this.cardinality = CARDINALITY_UNDEFINED;
        this.setActive(true);
    }

    public final String getRoleName() {
        return this.name;
    }
    
    protected final void setRoleName(String _name) {
        this.name = _name;
    }
    
    public final String getDescription() {
        return this.description;
    }
    
    public final void setDescription(String _description) {
        this.description = (_description == null ? null : 
        	_description.substring(0, Math.min(_description.length(), MAX_DESCRIPTION_TOSTRING)));
    }   
    
    public final boolean isActive() {
    	return this.active;
    }
    
    public final void setActive(boolean _active) {
    	this.active = _active;
    }
    
    public final int getStaticCardinality() {
    	return this.cardinality;
    }

    public final void setStaticCardinality(int _max) {
    	if (_max < CARDINALITY_UNDEFINED) {
    		_max = CARDINALITY_UNDEFINED;
    	}
    	this.cardinality = _max;
    }
    
    
//    public boolean isParent(BaseRole _child) {
//        for (Iterator it=this.childRoles.iterator(); it.hasNext();) {
//            BaseRole childRole = (BaseRole)it.next();
//            if (_child.equals(childRole)) {
//                return true;
//            }
//            if (childRole.isParent(_child)) {
//                return true;
//            }
//        }
//        return false;
//    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return 
        "BaseRole : [" +
        "name=" + this.getRoleName() + ";" +
        "description" + this.getDescription() +
        "]";
    }
    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object _otherRole) {
        return (this.compareTo(_otherRole)==0);
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return (37 + 37*this.getRoleName().hashCode());
    }
    
    /**
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(Object _otherRole) {
        Role otherRole = (Role)_otherRole;
        return this.getRoleName().compareTo(otherRole.getRoleName());
    }

}

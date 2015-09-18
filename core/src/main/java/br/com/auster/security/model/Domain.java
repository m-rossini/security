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
public class Domain extends CustomizableEntity implements Serializable, Comparable {

    

	
    protected String name;
    protected String description;    
    protected boolean active;

    
    
    public Domain(String _name) {
        this.setDomainName(_name);
        this.active = true;
    }

    public final String getDomainName() {
        return this.name;
    }
    protected final void setDomainName(String _name) {
        this.name = _name;
    }
    
    public final String getDescription() {
        return this.description;
    }
    public final void setDescription(String _description) {
        this.description = _description;
    }   
    
    public final boolean isActive() {
    	return this.active;
    }
    public final void setActive(boolean _active) {
    	this.active = _active;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return 
        "Domain : [" +
        "name=" + this.getDomainName() + ";" +
        "description" + this.getDescription() +
        "]";
    }
    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object _otherDomain) {
        return (this.compareTo(_otherDomain)==0);
    }
    
    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return (37 + 37*this.getDomainName().hashCode());
    }
    
    /**
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(Object _otherDomain) {
        Domain otherDomain = (Domain)_otherDomain;
        return this.getDomainName().compareTo(otherDomain.getDomainName());
    }

}

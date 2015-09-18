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
 * Created on 26/09/2006
 */
package br.com.auster.security.base;

import java.sql.Connection;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

import junit.framework.TestCase;
import br.com.auster.common.io.IOUtils;
import br.com.auster.common.log.LogFactory;
import br.com.auster.common.util.I18n;
import br.com.auster.common.xml.DOMUtils;
import br.com.auster.persistence.PersistenceService;
import br.com.auster.persistence.jdbc.DBCPJDBCPersistenceService;
import br.com.auster.security.interfaces.SecurityFacade;
import br.com.auster.security.model.Role;

/**
 * @author framos
 * @version $Id$
 */
public class SecurityFacadeImplDomainRoleTest extends TestCase {

	
	
	static PersistenceService ps;
	static SecurityFacade sf;
	
	private static final I18n i18n = I18n.getInstance(UserDAO.class);
	
	
	protected void setUp() throws Exception {
		LogFactory.configureLogSystem("/log4j.xml");
		Class.forName("oracle.jdbc.OracleDriver");
		Class.forName("org.apache.commons.dbcp.PoolingDriver");
		if (ps == null) {
			ps = new DBCPJDBCPersistenceService();
			ps.init(DOMUtils.openDocument(IOUtils.openFileForRead("base/testjdbc.xml")));
			Object connection = ps.openResourceConnection();
			TestInfoBuilder.clearDatabase((Connection)connection);
			ps.closeResourceConnection(connection);
		}
		if (sf == null) {
			sf = new BaseSecurityFacadeImpl(ps);
			sf.createRole(TestInfoBuilder.getAdminRole());
			sf.createRole(TestInfoBuilder.getGuestRole());
			sf.createRole(TestInfoBuilder.getAnalystRole());
			sf.createDomain(TestInfoBuilder.getReportViewDomain());
			sf.createDomain(TestInfoBuilder.getRequestMgmtDomain());
			sf.createDomain(TestInfoBuilder.getRequestViewDomain());
			sf.createDomain(TestInfoBuilder.getUserMgmtDomain());
		}		
	}
	
	
	
	// testing role assignment	
	public void testAssignRoleOK() {
		try {
			String domainName = TestInfoBuilder.getReportViewDomain().getDomainName();
			Role admin = TestInfoBuilder.getAdminRole();
			Role guest = TestInfoBuilder.getGuestRole();
			Calendar cal = Calendar.getInstance();
			Date today = cal.getTime();
			cal.add(Calendar.MONTH, 1);
			Date nextMonth = cal.getTime();
			// for ilimited time
			assertTrue(sf.grantDomain(domainName, admin.getRoleName()));
			// for a pre-defined period of time
			assertTrue(sf.grantDomain(domainName, guest.getRoleName(), today, nextMonth));
			// loading recently granted roles
			Collection c = sf.loadPermittedRoles(domainName);
			assertNotNull(c);
			assertEquals(2, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testAssignRoleWithNulls() {
		try {
			// user null
			try {
				sf.grantDomain(null, TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
			}
			// role null
			try {
				sf.grantDomain(TestInfoBuilder.getUserMgmtDomain().getDomainName(), null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
			}			
			// both null
			try {
				sf.grantDomain(null, null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
			}			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testAssignRoleWithDoesnotExist() {
		try {
			// user doesnot exist
			try {
				sf.grantDomain("doesnotExist", TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// role doesnot exist
			try {
				sf.grantDomain(TestInfoBuilder.getRequestMgmtDomain().getDomainName(), "doesnotExist");
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// both dont exist
			try {
				sf.grantDomain("doesnotExist", "doesnotExist");
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.doesnotExist", "doesnotExist"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	// testing role revoking	
	public void testRevokeDomainOK() {
		try {
			String domainName = TestInfoBuilder.getReportViewDomain().getDomainName();
			Role guest = TestInfoBuilder.getGuestRole();
			assertTrue(sf.revokeDomain(domainName, guest.getRoleName()));
			// loading active roles
			Collection c = sf.loadPermittedRoles(domainName);
			assertNotNull(c);
			assertEquals(1, c.size());
			// TODO look for history
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRevokeDomainWithNulls() {
		try {
			// user null
			try {
				sf.revokeDomain(null, TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
			}
			// role null
			try {
				sf.revokeDomain(TestInfoBuilder.getReportViewDomain().getDomainName(), null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
			}			
			// both null
			try {
				sf.revokeDomain(null, null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
			}			
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRevokeDomainWithDoesnotExist() {
		try {
			// user doesnot exist
			try {
				sf.revokeDomain("doesnotExist", TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// role doesnot exist
			try {
				sf.revokeDomain(TestInfoBuilder.getReportViewDomain().getDomainName(), "doesnotExist");
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// both dont exist
			try {
				sf.revokeDomain("doesnotExist", "doesnotExist");
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.doesnotExist", "doesnotExist"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	public void testRevokeDomainNotAssigned() {
		try {
			String domainname = TestInfoBuilder.getReportViewDomain().getDomainName();
			Role analyst = TestInfoBuilder.getAnalystRole();
			// user with roles, but not this one
			assertFalse(sf.revokeDomain(domainname, analyst.getRoleName()));
			// user without roles
			domainname = TestInfoBuilder.getUserMgmtDomain().getDomainName();
			assertFalse(sf.revokeDomain(domainname, analyst.getRoleName()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	public void testRevokeAgainAndReassign() {
		try {
			String domainname = TestInfoBuilder.getUserMgmtDomain().getDomainName();
			Role analyst = TestInfoBuilder.getAnalystRole();
			// assigning and re-assigning roles to test history
			assertTrue(sf.grantDomain(domainname, analyst.getRoleName()));
			Thread.sleep(1000);
			assertTrue(sf.revokeDomain(domainname, analyst.getRoleName()));
			Thread.sleep(1000);
			assertTrue(sf.grantDomain(domainname, analyst.getRoleName()));
			Thread.sleep(1000);
			assertTrue(sf.revokeDomain(domainname, analyst.getRoleName()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// testing role loading - when OK, tested previously
	public void testLoadRelationWithNulls() {
		try {
			sf.loadPermittedRoles(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testLoadRelationWithDoesnotExist() {
		try {
			Collection c = sf.loadActiveRoles("doesnotExist");
			assertNotNull(c);
			assertEquals(0, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		
}

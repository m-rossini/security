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
import java.util.Collection;

import junit.framework.TestCase;
import br.com.auster.common.io.IOUtils;
import br.com.auster.common.log.LogFactory;
import br.com.auster.common.util.I18n;
import br.com.auster.common.xml.DOMUtils;
import br.com.auster.persistence.FetchCriteria;
import br.com.auster.persistence.PersistenceService;
import br.com.auster.persistence.jdbc.DBCPJDBCPersistenceService;
import br.com.auster.security.interfaces.SecurityFacade;
import br.com.auster.security.model.Role;

/**
 * @author framos
 * @version $Id$
 */
public class SecurityFacadeImplRoleTest extends TestCase {

	
	
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
			sf.createRole(TestInfoBuilder.getAnalystRole());
			sf.createRole(TestInfoBuilder.getGuestRole());
		}		
	}
	

	
	
	// testing role creation	
	public void testRoleCreationOK() {
		try {
			Role role = TestInfoBuilder.getAdminRole();
			sf.createRole(role);
			assertTrue(role.getUid() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRoleDuplication() {
		Role role = TestInfoBuilder.getAdminRole();
		try {
			sf.createRole(role);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.role.alreadyRegistered", role.getRoleName()), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	public void testRoleCreationNull() {
		try {
			sf.createRole(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	// test role update
	public void testRoleUpdateOK() {
		try {
			Role role = TestInfoBuilder.getGuestRole();
			role.setCustom1(role.getDescription());
			role.setDescription("Convidados");
			sf.alterRole(role);
			role = sf.loadRole(role.getRoleName());
			assertEquals("Convidados", role.getDescription());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testRoleUpdateNull() {
		try {
			sf.alterRole(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	// test load role
	public void testLoadRoleOK() {
		try {
			Role role = TestInfoBuilder.getAdminRole();
			Role role2 = sf.loadRole(role.getRoleName());
			assertEquals(role.getRoleName(), role2.getRoleName());
			assertEquals(role.getDescription(), role2.getDescription());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testLoadRoleNull() {
			try {
				sf.loadRole(null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
				fail();
			}
	}
	
	public void testLoadRoleDoesnotExist() {
		try {
			Role role = sf.loadRole("doesnotExist");
			assertNull(role);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRoleBulkLoadOK() {
		try {
			Collection c = sf.loadRoles();
			assertNotNull(c);
			assertEquals(3, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRoleBulkLoadNullFetch() {
		try {
			Collection c = sf.loadRoles(null);
			assertNotNull(c);
			assertEquals(3, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testRoleBulkLoadFetchOrder() {
		try {
			FetchCriteria fc = new FetchCriteria();
			fc.addOrder(RoleDAO.ROLE_NAME_ATTR, true);
			Collection c = sf.loadRoles(fc);
			assertNotNull(c);
			assertEquals(3, c.size());
			
			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			c = sf.loadRoles(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			fc.addOrder(RoleDAO.ROLE_DESCRIPTION_ATTR, true);
			c = sf.loadRoles(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test count roles
	public void testRoleCount() {
		try {
			int c = sf.countRoles();
			assertEquals(3, c);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test remove roles
	public void testRemoveRoleWithNulls() {
		try {
			// from null
			try {
				sf.removeRole(null, TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
			}
			// to null
			try {
				sf.removeRole(TestInfoBuilder.getAdminRole().getRoleName(), null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.isNull"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testRemoveRoleWithDoesntExist() {
		try {
			// from null
			try {
				sf.removeRole("doesnotExist", TestInfoBuilder.getAdminRole().getRoleName());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// to null
			try {
				sf.removeRole(TestInfoBuilder.getAdminRole().getRoleName(), "doesnotExist");
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.role.doesnotExist", "doesnotExist"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRemoveRoleOK() {
		try {
			// role without users
			assertTrue(sf.removeRole(TestInfoBuilder.getAnalystRole().getRoleName(), 
					                 TestInfoBuilder.getAdminRole().getRoleName()));
			// role with users
			assertTrue(sf.removeRole(TestInfoBuilder.getAdminRole().getRoleName(), 
	                                 TestInfoBuilder.getGuestRole().getRoleName()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
}

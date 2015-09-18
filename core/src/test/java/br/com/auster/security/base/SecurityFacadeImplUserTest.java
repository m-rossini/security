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
import java.sql.SQLException;
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
import br.com.auster.security.model.PasswordInfo;
import br.com.auster.security.model.User;

/**
 * @author framos
 * @version $Id$
 */
public class SecurityFacadeImplUserTest extends TestCase {

	
	
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
			sf.createUser(TestInfoBuilder.getUser2(), TestInfoBuilder.getPassword());
			sf.createUser(TestInfoBuilder.getUser3(), TestInfoBuilder.getPassword());
		}		
	}
	
	// testing user creation	
	public void testUserCreationOK() {
		try {
			User user = TestInfoBuilder.getUser1();
			PasswordInfo password = TestInfoBuilder.getPassword();
			sf.createUser(user, password);
			assertTrue(user.getUid() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testUserDuplication() {
		User user = TestInfoBuilder.getUser1();
		try {
			PasswordInfo password = TestInfoBuilder.getPassword();
			sf.createUser(user, password);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.alreadyRegistered", user.getLogin()), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	public void testUserCreationUserNull() {
		try {
			PasswordInfo password = TestInfoBuilder.getPassword();
			sf.createUser(null, password);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testUserCreationPasswordNull() {
		try {
			User user = TestInfoBuilder.getUser1();
			sf.createUser(user, null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			i18n.getString("se.password.isNull");
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test user update
	public void testUserUpdateOK() {
		try {
			User user = sf.loadUser(TestInfoBuilder.getUser1().getLogin());
			user.setCustom1("custom1");
			user.setLastName("Another");
			sf.alterUser(user);
			user = sf.loadUser(user.getLogin());
			assertEquals("Another", user.getLastName());
			assertEquals("custom1", user.getCustom1());
			assertEquals("MyName", user.getFirstName());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testUserUpdateNull() {
		try {
			sf.alterUser(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testUserUpdateLoginNull() {
		try {
			User user = sf.loadUser(TestInfoBuilder.getUser1().getLogin());;
			user.setLogin(null);
			sf.alterUser(user);
			fail();
		} catch (SecurityException se) {
			assertNotNull(se.getCause());
			Throwable t = se.getCause();
			assertTrue(t instanceof SQLException);
			assertEquals(i18n.getString("dao.updateError"), t.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	// test load user
	public void testLoadUserOK() {
		try {
			User user = TestInfoBuilder.getUser1();
			User user2 = sf.loadUser(user.getLogin());
			assertEquals(user.getLogin(), user2.getLogin());
			assertEquals(user.getEmail(), user2.getEmail());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testLoadUserNull() {
			try {
				sf.loadUser(null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
				fail();
			}
	}
	
	public void testLoadUserDoesnotExist() {
		try {
			User user2 = sf.loadUser("doesnotExist");
			assertNull(user2);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testUserBulkLoadOK() {
		try {
			Collection c = sf.loadUsers();
			assertNotNull(c);
			assertEquals(3, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testUserBulkLoadNullFetch() {
		try {
			Collection c = sf.loadUsers(null);
			assertNotNull(c);
			assertEquals(3, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testUserBulkLoadFetchOrder() {
		try {
			FetchCriteria fc = new FetchCriteria();
			fc.addOrder(UserDAO.USER_LOGIN_ATTR, true);
			Collection c = sf.loadUsers(fc);
			assertNotNull(c);
			assertEquals(3, c.size());
			
			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			c = sf.loadUsers(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			fc.addOrder(UserDAO.USER_LOGIN_ATTR, true);
			c = sf.loadUsers(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test count users
	public void testUserCount() {
		try {
			int c = sf.countUsers();
			assertEquals(3, c);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test check password
	public void testPasswordCheckOK() {
		try {
			boolean isOK = sf.authenticate(TestInfoBuilder.getUser1().getLogin(), 
					                        TestInfoBuilder.getPassword().getPassword());
			assertTrue(isOK);
			// checking password status
			FetchCriteria currentPassword = new FetchCriteria();
			currentPassword.addOrder(PasswordDAO.PASSWORD_EXPIRDATE_ATTR, false);
			currentPassword.setSize(1);
			currentPassword.setOffset(0);
			Collection c = sf.loadPasswordHistory(TestInfoBuilder.getUser1().getLogin(), currentPassword);
			assertNotNull(c);
			assertEquals(1, c.size());
			PasswordInfo pw = (PasswordInfo) c.iterator().next();
			assertEquals(0, pw.getErrorCount());
			assertEquals(1, pw.getUsedCount());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	public void testPasswordCheckWrongPassword() {
		try {
			boolean isOK = sf.authenticate(TestInfoBuilder.getUser1().getLogin(), 
					                        "wrongpassword");
			assertFalse(isOK);
			FetchCriteria currentPassword = new FetchCriteria();
			currentPassword.addOrder(PasswordDAO.PASSWORD_EXPIRDATE_ATTR, false);
			currentPassword.setSize(1);
			currentPassword.setOffset(0);
			Collection c = sf.loadPasswordHistory(TestInfoBuilder.getUser1().getLogin(), currentPassword);
			assertNotNull(c);
			assertEquals(1, c.size());
			PasswordInfo pw = (PasswordInfo) c.iterator().next();
			assertEquals(1, pw.getErrorCount());
			assertEquals(2, pw.getUsedCount());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	public void testPasswordCheckUserNull() {
		try {
			sf.authenticate(null, TestInfoBuilder.getPassword().getPassword());
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testPasswordCheckPasswordNull() {
		try {
			sf.authenticate(TestInfoBuilder.getUser1().getLogin(), null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.password.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	public void testPasswordCheckInvalidUser() {
		try {
			sf.authenticate("doesnotExist", TestInfoBuilder.getPassword().getPassword());
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.doesnotExist", "doesnotExist"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test assign password
	public void testUpdatePasswordNullUser() {
		try {
			sf.assignPassword(null, TestInfoBuilder.getPassword(), null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	public void testUpdatePasswordNullPassword() {
		try {
			sf.assignPassword(TestInfoBuilder.getUser1().getLogin(), null, null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.password.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	

	public void testUpdatePasswordSecondPassword() {
		try {
			PasswordInfo p = TestInfoBuilder.getPassword();
			p.setPassword("passwd2");
			assertTrue(sf.assignPassword(TestInfoBuilder.getUser1().getLogin(), p, null));
			assertTrue(sf.authenticate(TestInfoBuilder.getUser1().getLogin(), 
                                        "passwd2"));
			assertTrue(sf.assignPassword(TestInfoBuilder.getUser1().getLogin(), 
            						     TestInfoBuilder.getPassword(), null));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testUpdatePasswordUserDoesntExist() {
		try {
			PasswordInfo p = TestInfoBuilder.getPassword();
			assertFalse(sf.assignPassword("doesnotExist", p, null));
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.doesnotExist", "doesnotExist"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	public void testPasswordHistoryOK() {
		try {
			String loginName = TestInfoBuilder.getUser1().getLogin();
			Collection c = sf.loadPasswordHistory(loginName);
			assertNotNull(c);
			assertEquals(3, c.size());
			// with fetch criteria
			FetchCriteria fetch = new FetchCriteria();
			fetch.setSize(2);
			fetch.setOffset(1);
			fetch.addOrder(PasswordDAO.PASSWORD_INSERTDATE_ATTR, true);
			c = sf.loadPasswordHistory(loginName, fetch);
			assertNotNull(c);
			assertEquals(2, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		

	public void testPasswordHistoryForNull() {
		try {
			sf.loadPasswordHistory(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		

	public void testPasswordHistoryForDoesntExist() {
		try {
			Collection c = sf.loadPasswordHistory("doesntExist");
			assertNotNull(c);
			assertEquals(0, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		
	
	// testing lock 
	public void testLockAndAuthenticateLockedOK() {
		try {
			assertTrue(sf.lockUser(TestInfoBuilder.getUser1().getLogin(), null));
			try {
				sf.authenticate(TestInfoBuilder.getUser1().getLogin(), 
						        TestInfoBuilder.getPassword().getPassword());
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.isLocked", TestInfoBuilder.getUser1().getLogin()), se.getMessage());
			}
			assertTrue(sf.unlockUser(TestInfoBuilder.getUser1().getLogin(), null));
			assertTrue(sf.authenticate(TestInfoBuilder.getUser1().getLogin(), 
						               TestInfoBuilder.getPassword().getPassword()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		
	
	public void testLockAndUnlockedNulls() {
		try {
			// lock NULL
			try {
				sf.lockUser(null, null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
			}
			// unlock NULL
			try {
				sf.unlockUser(null, null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.isNull"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		
	
	public void testLockAndUnlockedDoesntExist() {
		try {
			// lock NULL
			try {
				sf.lockUser("doesnotExist", null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.doesnotExist", "doesnotExist"), se.getMessage());
			}
			// unlock NULL
			try {
				sf.unlockUser("doesnotExist", null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.user.doesnotExist", "doesnotExist"), se.getMessage());
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}		
}

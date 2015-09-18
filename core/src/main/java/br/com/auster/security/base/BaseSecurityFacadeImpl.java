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
package br.com.auster.security.base;

import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeSet;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.FetchCriteria;
import br.com.auster.persistence.PersistenceResourceAccessException;
import br.com.auster.persistence.PersistenceService;
import br.com.auster.security.interfaces.SecurityFacade;
import br.com.auster.security.interfaces.SecurityPolicy;
import br.com.auster.security.model.Domain;
import br.com.auster.security.model.DomainRoleRelation;
import br.com.auster.security.model.PasswordInfo;
import br.com.auster.security.model.Role;
import br.com.auster.security.model.User;
import br.com.auster.security.model.UserRoleRelation;

/**
 * @author framos
 * @version $Id$
 */
public class BaseSecurityFacadeImpl implements SecurityFacade {



	private static final I18n i18n = I18n.getInstance(BaseSecurityFacadeImpl.class);


	protected UserDAO userDAO;
	protected RoleDAO roleDAO;
	protected PasswordDAO passwordDAO;
	protected UserRoleRelationDAO userroleDAO;
	protected DomainDAO domainDAO;
	protected DomainRoleRelationDAO domainroleDAO;
	protected PersistenceService persistence;
	protected SecurityPolicy policy;



	public BaseSecurityFacadeImpl(PersistenceService _persistence) {
		this.persistence = _persistence;
		this.userDAO = new UserDAO();
		this.roleDAO = new RoleDAO();
		this.passwordDAO = new PasswordDAO();
		this.userroleDAO = new UserRoleRelationDAO();
		this.domainDAO = new DomainDAO();
		this.domainroleDAO = new DomainRoleRelationDAO();
	}

	public void setPolicies(SecurityPolicy _policy) {
		this.policy = _policy;
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#createUser(br.com.auster.security.model.User,java.lang.String)
	 */
	public void createUser(User _user, PasswordInfo _password) throws SecurityException {
		if (_user == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		} else if (_password == null) {
			throw new SecurityException(i18n.getString("se.password.isNull"));
		}
		if (loadUser(_user.getLogin()) != null) {
			throw new SecurityException(i18n.getString("se.user.alreadyRegistered", _user.getLogin()));
		} else {
			Connection conn = null;
			Object tx = null;
			boolean allOk = true;
			try {
				if (conn == null) {
					conn = (Connection) this.persistence.openResourceConnection();
				}
				// applying expiration policies
				if (this.policy != null) {
					if (!this.policy.acceptPassword(_password.getPassword())) {
						throw new SecurityException(i18n.getString("se.password.policy.unnaceptable"));
					}
					this.policy.applyExpirationRules(_password, null);
				}
				tx = this.persistence.beginTransaction(conn);
				_user.setUid(this.userDAO.insertUser(conn, _user));
				// encrypting password
				_password.setPassword(encryptPassword(_user.getLogin(),_password.getPassword()));
				this.passwordDAO.updateUserPassword(conn, _user, _password);
			} catch (Exception e) {
				allOk = false;
				throw new SecurityException(e);
			} finally {
				try {
					if (allOk) {
						this.persistence.commitTransaction(tx);
					} else {
						this.persistence.rollbackTransaction(tx);
					}
					this.persistence.closeResourceConnection(conn);
				} catch (PersistenceResourceAccessException prae) {
					throw new SecurityException(prae);
				}
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#alterUser(br.com.auster.security.model.User)
	 */
	public boolean alterUser(User _user) throws SecurityException {
		if (_user == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		Connection conn = null;
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			return (this.userDAO.updateSingleUser(conn, _user) == 1);
		} catch (Exception e) {
			allOk = false;
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean lockUser(String _loginName, String _adminLogin) throws SecurityException {
		if (this.policy != null) {
			this.policy.acceptLock(this.loadUser(_loginName), _adminLogin);
		}
		return this.updateUserStatus(_loginName, true);
	}

	public boolean unlockUser(String _loginName, String _adminLogin)
			throws SecurityException {
		if (this.policy != null) {
			this.policy.acceptUnlock(this.loadUser(_loginName), _adminLogin);
		}
		return this.updateUserStatus(_loginName, false);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadUser(java.lang.String)
	 */
	public User loadUser(String _loginName) throws SecurityException {
		Connection conn = null;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user != null) {
				for (Iterator it = user.getRoles().iterator(); it.hasNext();) {
					Role r = (Role) it.next();
					Collection c = this.domainroleDAO.selectActivePermissionByRole(conn, r.getRoleName());
					for (Iterator it2 = user.getRoles().iterator(); it2.hasNext();) {
						DomainRoleRelation dr = (DomainRoleRelation) it2.next();
						user.getAllowedDomains().add(dr.getDomainName());
					}
				}
			}
			return user;
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadUserDetails(java.lang.String)
	 */
	public User loadUserDetails(String loginName) throws SecurityException {
		User user = null;

		if (loginName != null)
			loginName = loginName.toLowerCase();

		user = loadUser(loginName);

		if (user == null)
			return null;

		Collection userDomains = loadActiveUserDomains(loginName);
		Collection userRoles = loadActiveUserRoles(loginName);
		user.setAllowedDomains(new TreeSet(userDomains));
		user.setRoles(new TreeSet(userRoles));

		return user;
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#parseUserRemoteLogin(java.lang.String)
	 */
	public String parseUserRemoteLogin(String userLogin) {
		String parsedLogin = "";
		String[] parsedLoginAr = null;

		if (userLogin == null)
			return null;

		parsedLoginAr = userLogin.split("\\\\");

		if (parsedLoginAr.length == 0)
			return null;

		if (parsedLoginAr.length > 0) {
			parsedLogin = parsedLoginAr[parsedLoginAr.length - 1];

			if (parsedLogin != null)
				parsedLogin = parsedLogin.toLowerCase();
		}

		return parsedLogin;
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadUser(long)
	 */
	public User loadUser(long _uid) throws SecurityException {
		Connection conn = null;
		if (_uid <= 0) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.userDAO.selectSingleUser(conn, _uid);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadUsers()
	 */
	public Collection loadUsers() throws SecurityException {
		return loadUsers(null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadUsers(int, int)
	 */
	public Collection loadUsers(FetchCriteria _fetch) throws SecurityException {
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.userDAO.selectAllUsers(conn, _fetch);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#countUsers()
	 */
	public int countUsers() throws SecurityException {
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.userDAO.countUsers(conn);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
    }

    /**
     * @see br.com.auster.security.interfaces.SecurityFacade#assignPassword(java.lang.String, java.lang.String, java.lang.String)
     */
    public boolean assignPassword(String _loginName, PasswordInfo _password, String _admin) throws SecurityException {
    	return assignPassword(_loginName, _password, _admin, -1);
    }

    /**
	 * @see br.com.auster.security.interfaces.SecurityFacade#assignPassword(java.lang.String,
	 *      java.lang.String, java.lang.String, int)
	 */
	public boolean assignPassword(String _loginName, PasswordInfo _password, String _admin, int maxStoredPasswords) throws SecurityException {
		Connection conn = null;
		Object tx = null;
		boolean allOk = true;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		} else if (_password == null) {
			throw new SecurityException(i18n.getString("se.password.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user == null) {
				throw new SecurityException(i18n.getString("se.user.doesnotExist", _loginName));
			}
			// applying expiration policies
			if (this.policy != null) {
				if (!this.policy.acceptPassword(_password.getPassword())) {
					throw new SecurityException(i18n.getString("se.password.policy.unnaceptable"));
				}
				this.policy.applyExpirationRules(_password, _admin);
			}
			// encrypting password
			_password.setPassword(encryptPassword(user.getLogin(), _password.getPassword()));
			if (maxStoredPasswords == -1) {
    			return this.passwordDAO.updateUserPassword(conn, user, _password);
    		} else {
    			return this.passwordDAO.updateUserPassword(conn, user, _password, maxStoredPasswords);
    		}
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {this.persistence.commitTransaction(tx);
				} else {this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean validateCurrentPassword(String _loginName, String _typePassword) throws SecurityException {
		Connection conn = null;		
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			// checking password
			PasswordInfo passwd = this.passwordDAO.getCurrentPassword(conn, _loginName);
			if (passwd == null) {
				throw new SecurityException(i18n.getString("se.user.doesnotExist", _loginName));
			}
			return this.checkPassword(_loginName, passwd.getPassword(), _typePassword);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}		
	}
	
	public Collection loadPasswordHistory(String _loginName)
			throws SecurityException {
		return this.loadPasswordHistory(_loginName, null);
	}

	public Collection loadPasswordHistory(String _loginName,
			FetchCriteria _fetch) throws SecurityException {
		Connection conn = null;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.passwordDAO.selectPasswords(conn, _loginName, _fetch);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#authenticate(java.lang.String, java.lang.String)
	 */
	public boolean authenticate(String _loginName, String _password) throws SecurityException {
		Connection conn = null;
		Object tx = null;
		boolean allOk = true;
		try {
			if (_loginName == null) {
				throw new SecurityException(i18n.getString("se.user.isNull"));
			} else if (_password == null) {
				throw new SecurityException(i18n.getString("se.password.isNull"));
			}
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			// checking user
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user == null) {
				throw new SecurityException(i18n.getString("se.user.doesnotExist", _loginName));
			} else if (user.isLocked()) {
				throw new UserLockedException(i18n.getString("se.user.isLocked",_loginName));
			}
			// checking password
			PasswordInfo passwd = this.passwordDAO.getCurrentPassword(conn, _loginName);
			if (passwd == null) {
				throw new SecurityException(i18n.getString("se.user.doesnotExist", _loginName));
			}
			// checking expiration policies
			if (this.policy != null) {
				this.policy.acceptAuthenticate(user, passwd);
			}
			boolean pwdCheck = this.checkPassword(_loginName, passwd.getPassword(), _password);
			// updating error and used counts
			this.passwordDAO.updateErrorCount(conn, user.getUid(), passwd, pwdCheck);
			this.passwordDAO.updateUsedCounters(conn, user.getUid(), passwd);
			// returning authentication result
			return pwdCheck;
		} catch (Exception e) {
			allOk = false;
			try {
				this.persistence.rollbackTransaction(tx);
				tx = null;
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#createRole(br.com.auster.security.model.RoleBase)
	 */
	public void createRole(Role _role) throws SecurityException {
		Connection conn = null;
		if (_role == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			if (loadRole(_role.getRoleName()) != null) {
				throw new SecurityException(i18n.getString(
						"se.role.alreadyRegistered", _role.getRoleName()));
			} else {
				tx = this.persistence.beginTransaction(conn);
				conn = (Connection) this.persistence.openResourceConnection();
				this.roleDAO.insertRole(conn, _role);
			}
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#alterRole(br.com.auster.security.model.RoleBase)
	 */
	public boolean alterRole(Role _role) throws SecurityException {
		Connection conn = null;
		if (_role == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			int result = this.roleDAO.updateSingleRole(conn, _role);
			result += this.roleDAO.updateRoleStatus(conn, _role);
			return (result == 2);
		} catch (Exception e) {
			allOk = false;
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean removeRole(String _name, String _newRole) throws SecurityException {
		Connection conn = null;
		Object tx = null;
		boolean allOk = true;
		if ((_name == null) || (_newRole == null)) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			Role oldRole = this.roleDAO.selectSingleRoleByName(conn, _name);
			if (oldRole == null) {
				throw new SecurityException(i18n.getString("se.role.doesnotExist", _name));
			}
			Role newRole = this.roleDAO.selectSingleRoleByName(conn, _newRole);
			if (newRole == null) {
				throw new SecurityException(i18n.getString("se.role.doesnotExist", _newRole));
			}
			oldRole.setActive(false);
			this.userroleDAO.moveBetweenRoles(conn, oldRole.getUid(), newRole.getUid());
			allOk = (this.roleDAO.updateRoleStatus(conn, oldRole) == 1);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
		return allOk;
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRole(String)
	 */
	public Role loadRole(String _name) throws SecurityException {
		Connection conn = null;
		if (_name == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.roleDAO.selectSingleRoleByName(conn, _name);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles()
	 */
	public Collection loadRoles() throws SecurityException {
		return loadRoles(-1, null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles(FetchCriteria)
	 */
	public Collection loadRoles(FetchCriteria _fetch) throws SecurityException {
		return loadRoles(-1, _fetch);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRootRoles()
	 */
	public Collection loadRootRoles() throws SecurityException {
		return loadRoles(0, null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRootRoles(FetchCriteria)
	 */
	public Collection loadRootRoles(FetchCriteria _fetch)
			throws SecurityException {
		return loadRoles(0, _fetch);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles(int)
	 */
	public Collection loadRoles(int _levels) throws SecurityException {
		return loadRoles(_levels, null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles(int,FetchCriteria)
	 */
	public Collection loadRoles(int _levels, FetchCriteria _fetch)
			throws SecurityException {
		// TODO ignoring, for now, level information
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			// if (_levels < 0) {
			return this.roleDAO.selectAllRoles(conn, _fetch);
			// } else if (_levels == 0) {
			// return this.roleDAO.selectRootRoles(_fetch);
			// }
			// return this.roleDAO.selectAllRoles(_fetch);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#countRoles()
	 */
	public int countRoles() throws SecurityException {
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.roleDAO.countRoles(conn);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#grantRole(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean grantRole(String _user, String _role)
			throws SecurityException {
		return grantRole(_user, _role, Calendar.getInstance().getTime(), null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#grantRole(java.lang.String,
	 *      java.lang.String, java.util.Date, java.util.Date)
	 */
	public boolean grantRole(String _loginName, String _roleName, Date _from,
			Date _until) throws SecurityException {
		Connection conn = null;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		} else if (_roleName == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user == null) {
				throw new SecurityException(i18n.getString(
						"se.user.doesnotExist", _loginName));
			}
			Role role = this.roleDAO.selectSingleRoleByName(conn, _roleName);
			if (role == null) {
				throw new SecurityException(i18n.getString(
						"se.role.doesnotExist", _roleName));
			}
			if (!role.isActive()) {
				throw new SecurityException(i18n
						.getString("se.user.RoleisDeactivated"));
			}
			return (this.userroleDAO.assignPermission(conn, user.getUid(), role
					.getUid()) > 0);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#revokeRole(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean revokeRole(String _loginName, String _roleName)
			throws SecurityException {
		Connection conn = null;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		} else if (_roleName == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user == null) {
				throw new SecurityException(i18n.getString(
						"se.user.doesnotExist", _loginName));
			}
			Role role = this.roleDAO.selectSingleRoleByName(conn, _roleName);
			if (role == null) {
				throw new SecurityException(i18n.getString(
						"se.role.doesnotExist", _roleName));
			}
			return (this.userroleDAO.revokePermission(conn, user.getUid(), role
					.getUid()) > 0);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadActiveRoles(java.lang.String)
	 */
	public Collection loadActiveRoles(String _loginName) throws SecurityException {
		Connection conn = null;
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.userroleDAO.selectActivePermission(conn, _loginName);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public void createDomain(Domain _domain) throws SecurityException {
		Connection conn = null;
		if (_domain == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			if (loadDomain(_domain.getDomainName()) != null) {
				throw new SecurityException(i18n.getString(
						"se.domain.alreadyRegistered", _domain.getDomainName()));
			} else {
				conn = (Connection) this.persistence.openResourceConnection();
				tx = this.persistence.beginTransaction(conn);
				this.domainDAO.insertDomain(conn, _domain);
			}
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#alterRole(br.com.auster.security.model.RoleBase)
	 */
	public boolean alterDomain(Domain _domain) throws SecurityException {
		Connection conn = null;
		if (_domain == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			return (this.domainDAO.updateSingleDomain(conn, _domain) == 1);
		} catch (Exception e) {
			allOk = false;
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRole(String)
	 */
	public Domain loadDomain(String _domainName) throws SecurityException {
		Connection conn = null;
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.domainDAO.selectSingleDomainByName(conn, _domainName);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles()
	 */
	public Collection loadDomains() throws SecurityException {
		return loadDomains(null);
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#loadRoles(FetchCriteria)
	 */
	public Collection loadDomains(FetchCriteria _fetch)
			throws SecurityException {
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.domainDAO.selectAllDomains(conn, _fetch);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	/**
	 * @see br.com.auster.security.interfaces.SecurityFacade#countRoles()
	 */
	public int countDomains() throws SecurityException {
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.domainDAO.countDomains(conn);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean removeDomain(String _domainName) throws SecurityException {
		Connection conn = null;
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			Domain domain = this.domainDAO.selectSingleDomainByName(conn,
					_domainName);
			if (domain == null) {
				throw new SecurityException(i18n.getString(
						"se.domain.doesnotExist", _domainName));
			}
			return (this.domainDAO.deactivateDomain(conn, domain) == 1);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean grantDomain(String _domainName, String _roleName)
			throws SecurityException {
		return grantDomain(_domainName, _roleName, Calendar.getInstance()
				.getTime(), null);
	}

	public boolean grantDomain(String _domainName, String _roleName,
			Date _from, Date _until) throws SecurityException {
		Connection conn = null;
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		} else if (_roleName == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			Domain domain = this.domainDAO.selectSingleDomainByName(conn,
					_domainName);
			if (domain == null) {
				throw new SecurityException(i18n.getString(
						"se.domain.doesnotExist", _domainName));
			}
			Role role = this.roleDAO.selectSingleRoleByName(conn, _roleName);
			if (role == null) {
				throw new SecurityException(i18n.getString(
						"se.role.doesnotExist", _roleName));
			}
			if (!role.isActive()) {
				throw new SecurityException(i18n
						.getString("se.domain.RoleisDeactivated"));
			}
			return (this.domainroleDAO.assignPermission(conn, domain.getUid(),
					role.getUid()) > 0);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean revokeDomain(String _domainName, String _roleName)
			throws SecurityException {
		Connection conn = null;
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		} else if (_roleName == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			Domain domain = this.domainDAO.selectSingleDomainByName(conn,
					_domainName);
			if (domain == null) {
				throw new SecurityException(i18n.getString(
						"se.domain.doesnotExist", _domainName));
			}
			Role role = this.roleDAO.selectSingleRoleByName(conn, _roleName);
			if (role == null) {
				throw new SecurityException(i18n.getString(
						"se.role.doesnotExist", _roleName));
			}
			return (this.domainroleDAO.revokePermission(conn, domain.getUid(),
					role.getUid()) > 0);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public Collection loadPermittedRoles(String _domainName)
			throws SecurityException {
		Connection conn = null;
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.domainroleDAO.selectActivePermission(conn, _domainName);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public Collection loadActiveUserRoles(String loginName) throws SecurityException {
		Connection conn = null;
		Collection userRoles = new LinkedList();
		if (loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			Collection activeRoles = loadActiveRoles(loginName);
			Iterator rolesIt = activeRoles.iterator();

			while (rolesIt.hasNext()) {
				UserRoleRelation userRole = (UserRoleRelation) rolesIt.next();
				long roleId = userRole.getRoleUid();
				Role role = this.roleDAO.selectRoleById(conn, roleId);
				userRoles.add(role);
			}

			return userRoles;
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public Collection loadActiveUserDomains(String loginName)
			throws SecurityException {
		Connection conn = null;
		Collection userDomains = new LinkedList();
		if (loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			Collection activeRoles = loadActiveRoles(loginName);
			Iterator rolesIt = activeRoles.iterator();

			while (rolesIt.hasNext()) {
				UserRoleRelation userRole = (UserRoleRelation) rolesIt.next();
				long roleId = userRole.getRoleUid();
				Role role = this.roleDAO.selectRoleById(conn, roleId);
				Collection roleDomains = loadActiveDomains(role.getRoleName());
				Iterator domainIt = roleDomains.iterator();

				while (domainIt.hasNext()) {
					DomainRoleRelation domainRel = (DomainRoleRelation) domainIt
							.next();
					userDomains.add(domainRel.getDomainName());
				}
			}

			return userDomains;
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public Collection loadActiveDomains(String _roleName)
			throws SecurityException {
		Connection conn = null;
		if (_roleName == null) {
			throw new SecurityException(i18n.getString("se.role.isNull"));
		}
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			return this.domainroleDAO.selectActivePermissionByRole(conn, _roleName);
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	public boolean authorize(String _loginName, String _domainName)
			throws SecurityException {
		if (_domainName == null) {
			throw new SecurityException(i18n.getString("se.domain.isNull"));
		} else if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		Collection userRoles = this.loadActiveRoles(_loginName);
		if ((userRoles == null) || (userRoles.size() < 1)) {
			throw new SecurityException(i18n.getString("se.user.doesnotExist",
					_loginName));
		}
		Collection rolesPermitted = this.loadPermittedRoles(_domainName);
		if ((rolesPermitted == null) || (rolesPermitted.size() < 1)) {
			throw new SecurityException(i18n.getString(
					"se.domain.doesnotExist", _domainName));
		}
		for (Iterator i = userRoles.iterator(); i.hasNext();) {
			if (!rolesPermitted.contains(i.next())) {
				continue;
			}
			return true;
		}
		return false;
	}

	// Protected methods
	protected boolean updateUserStatus(String _loginName, boolean _toLock)
			throws SecurityException {
		if (_loginName == null) {
			throw new SecurityException(i18n.getString("se.user.isNull"));
		}
		Connection conn = null;
		Object tx = null;
		boolean allOk = true;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			tx = this.persistence.beginTransaction(conn);
			User user = this.userDAO.selectSingleUserByLogin(conn, _loginName);
			if (user == null) {
				throw new SecurityException(i18n.getString("se.user.doesnotExist", _loginName));
			}
			user.setLocked(_toLock);
			// when unlocking, reset error count
			if (!_toLock) {
				this.passwordDAO.updateErrorCount(conn, user.getUid(), this.passwordDAO.getCurrentPassword(conn, _loginName), true);
			}
			return (this.userDAO.updateUserStatus(conn, user) == 1);
		} catch (Exception e) {
			allOk = false;
			if (e instanceof SecurityException) {
				throw (SecurityException) e;
			}
			throw new SecurityException(e);
		} finally {
			try {
				if (allOk) {
					this.persistence.commitTransaction(tx);
				} else {
					this.persistence.rollbackTransaction(tx);
				}
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

	protected String encryptPassword(String _email, String _password)
			throws NoSuchAlgorithmException {
		return EncryptAlgorithms.getMD5Digest(_email + "/" + _password);
	}

	protected boolean checkPassword(String _loginName, String _correctPassword,
			String _typedPassword) throws SecurityException {
		try {
			return ((_correctPassword != null) && _correctPassword
					.equals(encryptPassword(_loginName, _typedPassword)));
		} catch (NoSuchAlgorithmException nsae) {
			throw new SecurityException(nsae);
		}
	}

	public List userByRole(String role, String userEvent)
			throws SecurityException {
		if (role == null) {
			throw new SecurityException(i18n.getString("se.roler.isNull"));
		}
		Connection conn = null;
		try {
			conn = (Connection) this.persistence.openResourceConnection();
			List userByRole = this.userroleDAO.userRole(conn, role, userEvent);
			return userByRole;
		} catch (Exception e) {
			throw new SecurityException(e);
		} finally {
			try {
				this.persistence.closeResourceConnection(conn);
			} catch (PersistenceResourceAccessException prae) {
				throw new SecurityException(prae);
			}
		}
	}

}

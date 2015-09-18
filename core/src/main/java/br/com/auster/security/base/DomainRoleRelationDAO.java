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
 * Created on 20/04/2006
 */
package br.com.auster.security.base;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.PersistenceResourceAccessException;
import br.com.auster.persistence.jdbc.JDBCQueryHelper;
import br.com.auster.security.model.DomainRoleRelation;

/**
 * @author framos
 * @verion $Id$
 */
public class DomainRoleRelationDAO {
	

	
	protected static ResourceBundle rb;
	static {
		String pckName = DomainRoleRelation.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}
	
	public static final String DOMAINROLE_TABLENAME = 
		JDBCQueryHelper.createSQL("${DomainRoleRelation.TABLENAME}", rb);
	public static final String DOMAINROLE_DOMAINUID_ATTR = 
		JDBCQueryHelper.createSQL("${DomainRoleRelation.domainUid}", rb);
	public static final String DOMAINROLE_ROLEUID_ATTR = 
		JDBCQueryHelper.createSQL("${DomainRoleRelation.roleUid}", rb);
	public static final String DOMAINROLE_ASSIGNDATE_ATTR = 
		JDBCQueryHelper.createSQL("${DomainRoleRelation.assignDate}", rb);
	public static final String DOMAINROLE_EXPIRATIONDATE_ATTR = 
		JDBCQueryHelper.createSQL("${DomainRoleRelation.expirationDate}", rb);
	
	
	protected static final String DOMAINROLE_SELECT_ALL_BY_DOMAIN =
		JDBCQueryHelper.createSQL("select ${DomainRoleRelation.TABLENAME}.*, " +
			" ${Role.TABLENAME}.${Role.name}, ${Domain.TABLENAME}.${Domain.name} from ${DomainRoleRelation.TABLENAME} " +
			" join ${Domain.TABLENAME} on ${Domain.TABLENAME}.${Domain.uid} = ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.domainUid}" + 
			" join ${Role.TABLENAME} on ${Role.TABLENAME}.${Role.uid} = ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.roleUid}" + 
			" where ${Domain.TABLENAME}.${Domain.name} = ?", rb);
	
	protected static final String DOMAINROLE_SELECT_ACTIVE_BY_DOMAIN = 
		JDBCQueryHelper.createSQL(DOMAINROLE_SELECT_ALL_BY_DOMAIN + " " +
			" and ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.expirationDate} is null", rb);

	protected static final String DOMAINROLE_SELECT_ACTIVE_BY_ROLE = 
		JDBCQueryHelper.createSQL("select ${DomainRoleRelation.TABLENAME}.*, " +
				" ${Role.TABLENAME}.${Role.name}, ${Domain.TABLENAME}.${Domain.name} from ${DomainRoleRelation.TABLENAME} " +
				" join ${Domain.TABLENAME} on ${Domain.TABLENAME}.${Domain.uid} = ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.domainUid}" + 
				" join ${Role.TABLENAME} on ${Role.TABLENAME}.${Role.uid} = ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.roleUid}" + 
				" where ${Role.TABLENAME}.${Role.name} = ?" +
			    " and ${DomainRoleRelation.TABLENAME}.${DomainRoleRelation.expirationDate} is null", rb);
	
	protected static final String DOMAINROLE_ASSIGN =
		JDBCQueryHelper.createSQL("insert into ${DomainRoleRelation.TABLENAME} ( " +
			" ${DomainRoleRelation.assignDate}, ${DomainRoleRelation.expirationDate}, " + 
			" ${DomainRoleRelation.domainUid}, ${DomainRoleRelation.roleUid} ) " +
			" values ( ? , null, ?, ? )", rb);

	protected static final String DOMAINROLE_REVOKE =
		JDBCQueryHelper.createSQL("update ${DomainRoleRelation.TABLENAME} set " +
			"${DomainRoleRelation.expirationDate} = ? where " + 
			"${DomainRoleRelation.domainUid} = ? and ${DomainRoleRelation.roleUid} = ? and " +
			"${DomainRoleRelation.expirationDate} is null", rb);
	
	protected static final String USERROLE_BULK_REVOKE =
		JDBCQueryHelper.createSQL("update ${DomainRoleRelation.TABLENAME} set " +
			"${DomainRoleRelation.expirationDate} = ? where " + 
			"${DomainRoleRelation.roleUid} = ? and ${DomainRoleRelation.expirationDate} is null",
			rb);

	private static final Logger log = Logger.getLogger(DomainRoleRelationDAO.class);
	
	
	
	
	public Collection selectPermissionHistory(Connection _conn, String _name) throws SQLException, PersistenceResourceAccessException {
		return this.selectPermissionInfo(_conn, _name, DOMAINROLE_SELECT_ALL_BY_DOMAIN);
	}

	public Collection selectActivePermission(Connection _conn, String _name) throws SQLException, PersistenceResourceAccessException {
		return this.selectPermissionInfo(_conn, _name, DOMAINROLE_SELECT_ACTIVE_BY_DOMAIN);
	}

	public Collection selectActivePermissionByRole(Connection _conn, String _name) throws SQLException, PersistenceResourceAccessException {
		return this.selectPermissionInfo(_conn, _name, DOMAINROLE_SELECT_ACTIVE_BY_ROLE);
	}
	
	public int assignPermission(Connection _conn, long _domainId, long _roleId) throws SQLException, PersistenceResourceAccessException {
		return updatePermissionToUser(_conn, _domainId, _roleId, DOMAINROLE_ASSIGN);
	}

	public int revokePermission(Connection _conn, long _domainId, long _roleId) throws SQLException, PersistenceResourceAccessException {
		return updatePermissionToUser(_conn, _domainId, _roleId, DOMAINROLE_REVOKE);
	}

	public int revokeFromAllRoles(Connection _conn, long _domainUid) throws SQLException, PersistenceResourceAccessException {		
		PreparedStatement stmt = null;
		try {
			stmt = _conn.prepareStatement(USERROLE_BULK_REVOKE);
			stmt.setTimestamp(1, new Timestamp(Calendar.getInstance().getTimeInMillis()));
			stmt.setLong(2, _domainUid);
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}
	
	private Collection selectPermissionInfo(Connection _conn, String _name, String _sql) throws SQLException, PersistenceResourceAccessException {
		Collection userRoles = new LinkedList();
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			stmt.setString(1, _name);
			rset = stmt.executeQuery();
			while (rset.next()) {
				userRoles.add(loadUserPermissionFromResultset(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return userRoles;
	}
	
	private DomainRoleRelation loadUserPermissionFromResultset(ResultSet _rset) throws SQLException {
		DomainRoleRelation urole = new DomainRoleRelation(_rset.getLong(DOMAINROLE_DOMAINUID_ATTR), 
				                                      _rset.getLong(DOMAINROLE_ROLEUID_ATTR));
		urole.setAssignDate(_rset.getTimestamp(DOMAINROLE_ASSIGNDATE_ATTR));
		urole.setExpirationDate(_rset.getTimestamp(DOMAINROLE_EXPIRATIONDATE_ATTR));
		urole.setRoleName(_rset.getString(RoleDAO.ROLE_NAME_ATTR));
		urole.setDomainName(_rset.getString(DomainDAO.DOMAIN_NAME_ATTR));
		return urole;
	}

	private int updatePermissionToUser(Connection _conn, long _domainId, long _roleId, String _sql) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);			
			stmt.setTimestamp(1, new Timestamp(Calendar.getInstance().getTimeInMillis()));
			stmt.setLong(2, _domainId);
			stmt.setLong(3, _roleId);
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}	
	
	private final void debugSQL(String _sql) {
		log.debug("Executing sql: " + _sql);
	}	
}

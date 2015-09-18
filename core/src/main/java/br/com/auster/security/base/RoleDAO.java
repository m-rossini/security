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
import java.text.MessageFormat;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import br.com.auster.common.util.I18n;
import br.com.auster.persistence.FetchCriteria;
import br.com.auster.persistence.PersistenceResourceAccessException;
import br.com.auster.persistence.jdbc.JDBCQueryHelper;
import br.com.auster.persistence.jdbc.JDBCSequenceHelper;
import br.com.auster.security.model.Role;

/**
 * @author framos
 * @verion $Id$
 */
public class RoleDAO {


	protected static ResourceBundle rb;
	static {
		String pckName = Role.class.getPackage().getName();
		rb = I18n.searchResourceBundle(pckName, "QueriesBundle", Locale.getDefault());
	}

	// public attributes defining table name, its columns and the sequence
	//    from where UIDs will be generated
	public static final String ROLE_SEQUENCE  =
		JDBCQueryHelper.createSQL("${Role.SEQUENCE}", rb);
	public static final String ROLE_TABLENAME =
		JDBCQueryHelper.createSQL("${Role.TABLENAME}", rb);
	public static final String ROLE_UID_ATTR =
		JDBCQueryHelper.createSQL("${Role.uid}", rb);
	public static final String ROLE_NAME_ATTR =
		JDBCQueryHelper.createSQL("${Role.name}", rb);
	public static final String ROLE_STATIC_CARDINALITY_ATTR =
		JDBCQueryHelper.createSQL("${Role.cardinality}", rb);
	public static final String ROLE_DESCRIPTION_ATTR =
		JDBCQueryHelper.createSQL("${Role.description}", rb);
	public static final String ROLE_ACTIVE_ATTR =
		JDBCQueryHelper.createSQL("${Role.active}", rb);
	public static final String ROLE_CUSTOM1_ATTR =
		JDBCQueryHelper.createSQL("${Role.custom1}", rb);
	public static final String ROLE_CUSTOM2_ATTR =
		JDBCQueryHelper.createSQL("${Role.custom2}", rb);
	public static final String ROLE_CUSTOM3_ATTR =
		JDBCQueryHelper.createSQL("${Role.custom3}", rb);

	protected static final String ROLE_SELECTALL =
		JDBCQueryHelper.createSQL("select * from ${Role.TABLENAME}", rb);

	protected static final String ROLE_COUNT =
		JDBCQueryHelper.createSQL("select count(*) from ${Role.TABLENAME}", rb);

	protected static final String ROLE_SELECT_BY_NAME =
		JDBCQueryHelper.createSQL(ROLE_SELECTALL + " where ${Role.name} = ?", rb);

	protected static final String ROLE_SELECT_BY_ID =
		JDBCQueryHelper.createSQL(ROLE_SELECTALL + " where OBJID = ?", rb);

	protected static final String ROLE_UPDATE_INFO =
		JDBCQueryHelper.createSQL(
			"update ${Role.TABLENAME} set " +
			" ${Role.description} = ?, ${Role.custom1} = ?, " +
			" ${Role.custom2} = ?, ${Role.custom3} = ?, " +
			" ${Role.cardinality} = ? where ${Role.name} = ?", rb);

	protected static final String ROLE_INSERT_INFO =
		JDBCQueryHelper.createSQL(
			"insert into  ${Role.TABLENAME} (" +
			" ${Role.active}, ${Role.description}, ${Role.custom1}, ${Role.custom2}, " +
			" ${Role.custom3}, ${Role.cardinality}, ${Role.name}, " +
			" ${Role.uid} ) values ( ?, ?, ?, ?, ?, ?, ?, '{'0'}' )", rb);

	protected static final String ROLE_UPDATE_STATUS =
		JDBCQueryHelper.createSQL(
			"update ${Role.TABLENAME} set ${Role.active} = ? where ${Role.name} = ?", rb);


	private static final Logger log = Logger.getLogger(RoleDAO.class);
	private static final I18n i18n = I18n.getInstance(RoleDAO.class);



	public Role selectSingleRoleByName(Connection conn, String _name) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(ROLE_SELECT_BY_NAME);
			stmt = conn.prepareStatement(ROLE_SELECT_BY_NAME);
			stmt.setString(1, _name);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return loadRoleFromResultset(rset);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return null;
	}



	public Role selectRoleById(Connection conn, long roleId) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(ROLE_SELECT_BY_ID);
			stmt = conn.prepareStatement(ROLE_SELECT_BY_ID);
			stmt.setLong(1, roleId);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return loadRoleFromResultset(rset);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return null;
	}

	public Collection selectAllRoles(Connection conn, FetchCriteria _fetch) throws SQLException, PersistenceResourceAccessException {
		return doSelect(conn, _fetch, ROLE_SELECTALL);
	}

	public int countRoles(Connection conn) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(ROLE_COUNT);
			stmt = conn.prepareStatement(ROLE_COUNT);
			rset = stmt.executeQuery();
			if (rset.next()) {
				return rset.getInt(1);
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return 0;
	}

	public int updateSingleRole(Connection conn, Role _role) throws SQLException, PersistenceResourceAccessException {
		if (executeSingleUpdate(conn, ROLE_UPDATE_INFO, _role, true) != 1) {
			throw new SQLException(i18n.getString("dao.updateError"));
		}
		return 1;
	}

	public long insertRole(Connection conn, Role _role) throws SQLException, PersistenceResourceAccessException {
		long uid = JDBCSequenceHelper.nextValue(conn, ROLE_SEQUENCE);
		_role.setUid(uid);
		String sql = MessageFormat.format(ROLE_INSERT_INFO, new Object[] { String.valueOf(uid) } );
		if (executeSingleUpdate(conn, sql, _role, false) != 1) {
			throw new SQLException(i18n.getString("dao.notInserted"));
		}
		return uid;
	}

	public int updateRoleStatus(Connection _conn, Role _role) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		try {
			debugSQL(ROLE_UPDATE_STATUS);
			stmt = _conn.prepareStatement(ROLE_UPDATE_STATUS);
			int colIdx = 1;
			stmt.setString(colIdx++, decodeActiveFlag(_role.isActive()));
			stmt.setString(colIdx++, _role.getRoleName());
			return stmt.executeUpdate();
		} finally {
			if (stmt != null) { stmt.close(); }
		}
	}

	private int executeSingleUpdate(Connection _conn, String _sql, Role _role, boolean _skipStatus) throws SQLException, PersistenceResourceAccessException {
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			debugSQL(_sql);
			stmt = _conn.prepareStatement(_sql);
			int colIdx = 1;
			if (!_skipStatus) {
				stmt.setString(colIdx++, decodeActiveFlag(_role.isActive()));
			}
			stmt.setString(colIdx++, _role.getDescription());
			stmt.setString(colIdx++, _role.getCustom1());
			stmt.setString(colIdx++, _role.getCustom2());
			stmt.setString(colIdx++, _role.getCustom3());
			stmt.setInt(colIdx++, _role.getStaticCardinality());
			stmt.setString(colIdx++, _role.getRoleName());
			return stmt.executeUpdate();
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
	}

	private final String decodeActiveFlag(boolean _active) {
		return (_active ? "A" : "D");
	}

	private final boolean encodeActiveFlag(String _active) {
		return ((_active != null) &&  "A".equals(_active));
	}

	private Role loadRoleFromResultset(ResultSet _rset) throws SQLException {
		Role role = new Role(_rset.getString(ROLE_NAME_ATTR));
		// setting BaseUser attributes
		role.setDescription(_rset.getString(ROLE_DESCRIPTION_ATTR));
		role.setStaticCardinality(_rset.getInt(ROLE_STATIC_CARDINALITY_ATTR));
		role.setActive(encodeActiveFlag(_rset.getString(ROLE_ACTIVE_ATTR)));
		// setting CustomizableEntity attributes
		role.setUid(_rset.getLong(ROLE_UID_ATTR));
		role.setCustom1(_rset.getString(ROLE_CUSTOM1_ATTR));
		role.setCustom2(_rset.getString(ROLE_CUSTOM2_ATTR));
		role.setCustom3(_rset.getString(ROLE_CUSTOM3_ATTR));
		return role;
	}

	private Collection doSelect(Connection conn, FetchCriteria _fetch, String _sql) throws SQLException, PersistenceResourceAccessException {
		Collection selectedRoles = new LinkedList();
		PreparedStatement stmt = null;
		ResultSet rset = null;
		try {
			String sql = JDBCQueryHelper.applyFetchParameters(conn, _sql, _fetch);
			debugSQL(sql);
			stmt = conn.prepareStatement(sql);
			rset = stmt.executeQuery();
			while (rset.next()) {
				selectedRoles.add(loadRoleFromResultset(rset));
			}
		} finally {
			if (rset != null) { rset.close(); }
			if (stmt != null) { stmt.close(); }
		}
		return selectedRoles;
	}

	private final void debugSQL(String _sql) {
		log.debug(i18n.getString("debug.sql", _sql));
	}
}

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
import br.com.auster.security.model.Domain;

/**
 * @author framos
 * @version $Id$
 */
public class SecurityFacadeImplDomainTest extends TestCase {

	
	
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
			sf.createDomain(TestInfoBuilder.getReportViewDomain());
			sf.createDomain(TestInfoBuilder.getRequestMgmtDomain());
			sf.createDomain(TestInfoBuilder.getRequestViewDomain());
		}		
	}
	
	
	// testing domain creation	
	public void testDomainCreationOK() {
		try {
			Domain domain = TestInfoBuilder.getUserMgmtDomain();
			sf.createDomain(domain);
			assertTrue(domain.getUid() > 0);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testDomainDuplication() {
		Domain domain = TestInfoBuilder.getReportViewDomain();
		try {
			sf.createDomain(domain);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.alreadyRegistered", domain.getDomainName()), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	public void testDomainCreationNull() {
		try {
			sf.createDomain(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	// test domain update
	public void testDomainUpdateOK() {
		try {
			Domain domain = TestInfoBuilder.getRequestMgmtDomain();
			domain.setCustom1(domain.getDescription());
			domain.setDescription("Convidados");
			sf.alterDomain(domain);
			domain = sf.loadDomain(domain.getDomainName());
			assertEquals("Convidados", domain.getDescription());
			assertEquals("Can run on-demand requests", domain.getCustom1());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testDomainUpdateNull() {
		try {
			sf.alterDomain(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	// test load domain
	public void testLoadDomainOK() {
		try {
			Domain domain = TestInfoBuilder.getRequestViewDomain();
			Domain domain2 = sf.loadDomain(domain.getDomainName());
			assertEquals(domain.getDomainName(), domain2.getDomainName());
			assertEquals(domain.getDescription(), domain2.getDescription());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testLoadDomainNull() {
			try {
				sf.loadDomain(null);
				fail();
			} catch (SecurityException se) {
				assertNull(se.getCause());
				assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
				fail();
			}
	}
	
	public void testLoadDomainDoesnotExist() {
		try {
			Domain domain = sf.loadDomain("doesnotExist");
			assertNull(domain);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testDomainBulkLoadOK() {
		try {
			Collection c = sf.loadDomains();
			assertNotNull(c);
			assertEquals(4, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testDomainBulkLoadNullFetch() {
		try {
			Collection c = sf.loadDomains(null);
			assertNotNull(c);
			assertEquals(4, c.size());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testDomainBulkLoadFetchOrder() {
		try {
			FetchCriteria fc = new FetchCriteria();
			fc.addOrder(DomainDAO.DOMAIN_NAME_ATTR, true);
			Collection c = sf.loadDomains(fc);
			assertNotNull(c);
			assertEquals(4, c.size());
			
			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			c = sf.loadDomains(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

			fc = new FetchCriteria();
			fc.setOffset(0);
			fc.setSize(2);
			fc.addOrder(DomainDAO.DOMAIN_DESCRIPTION_ATTR, true);
			c = sf.loadDomains(fc);
			assertNotNull(c);			
			assertEquals(2, c.size());

		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test count Domains
	public void testDomainCount() {
		try {
			int c = sf.countDomains();
			assertEquals(4, c);
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}	
	
	// test remove Domains
	public void testRemoveDomainWithNulls() {
		try {
			sf.removeDomain(null);
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.isNull"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
	public void testRemoveDomainWithDoesntExist() {
		try {
			sf.removeDomain("doesnotExist");
			fail();
		} catch (SecurityException se) {
			assertNull(se.getCause());
			assertEquals(i18n.getString("se.domain.doesnotExist", "doesnotExist"), se.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	public void testRemoveDomainOK() {
		try {
			assertTrue(sf.removeDomain(TestInfoBuilder.getRequestMgmtDomain().getDomainName()));
		} catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}
	
}

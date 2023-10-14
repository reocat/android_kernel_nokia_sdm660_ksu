/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <soc/qcom/secure_buffer.h>
#include "msm_drv.h"
#include "msm_iommu.h"

static int msm_fault_handler(struct iommu_domain *domain, struct device *dev,
		unsigned long iova, int flags, void *arg)
{
	struct msm_iommu *iommu = arg;
	if (iommu->base.handler)
		return iommu->base.handler(iommu->base.arg, iova, flags);
	pr_warn_ratelimited("*** fault: iova=%08lx, flags=%d\n", iova, flags);
	return 0;
}

static int msm_iommu_attach(struct msm_mmu *mmu, const char * const *names,
			    int cnt)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	int ret;
	u32 prot = IOMMU_READ;

	pm_runtime_get_sync(mmu->dev);
	ret = iommu_attach_device(iommu->domain, mmu->dev);
	pm_runtime_put_sync(mmu->dev);

	return ret;
}

static void msm_iommu_detach(struct msm_mmu *mmu, const char * const *names,
			     int cnt)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);

	pm_runtime_get_sync(mmu->dev);
	iommu_detach_device(iommu->domain, mmu->dev);
	pm_runtime_put_sync(mmu->dev);
}

static int msm_iommu_map(struct msm_mmu *mmu, uint64_t iova,
		struct sg_table *sgt, unsigned len, int prot)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	size_t ret;

//	pm_runtime_get_sync(mmu->dev);
	ret = iommu_map_sg(iommu->domain, iova, sgt->sgl, sgt->nents, prot);
//	pm_runtime_put_sync(mmu->dev);
	WARN_ON(!ret);

	return (ret == len) ? 0 : -EINVAL;
}

static int msm_iommu_unmap(struct msm_mmu *mmu, uint64_t iova,
		struct sg_table *sgt, unsigned len)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);

	pm_runtime_get_sync(mmu->dev);
	iommu_unmap(iommu->domain, iova, len);
	pm_runtime_put_sync(mmu->dev);

	return 0;
}

static void msm_iommu_destroy(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	iommu_domain_free(iommu->domain);
	kfree(iommu);
}

static struct device *find_context_bank(const char *name)
{
	struct device_node *node = of_find_node_by_name(NULL, name);
	struct platform_device *pdev, *parent;

	if (!node)
		return ERR_PTR(-ENODEV);

	if (!of_find_property(node, "iommus", NULL))
		return ERR_PTR(-ENODEV);

	/* Get the parent device */
	parent = of_find_device_by_node(node->parent);
	if (!parent)
		return ERR_PTR(-ENODEV);
	/* Populate the sub nodes */
	of_platform_populate(parent->dev.of_node, NULL, NULL, &parent->dev);

	/* Get the context bank device */
	pdev = of_find_device_by_node(node);

	return pdev ? &pdev->dev : ERR_PTR(-ENODEV);
}

static const struct msm_mmu_funcs default_funcs = {
		.attach = msm_iommu_attach,
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

static const struct msm_mmu_funcs user_funcs = {
		.attach = msm_iommu_attach_user,
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
		.enable = msm_iommu_clocks_enable,
		.disable = msm_iommu_clocks_disable,
};

static const struct msm_mmu_funcs secure_funcs = {
		.attach = msm_iommu_attach_secure,
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

static const struct msm_mmu_funcs dynamic_funcs = {
		.attach = msm_iommu_attach_dynamic,
		.detach = msm_iommu_detach_dynamic,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

static const struct {
	const char *cbname;
	const struct msm_mmu_funcs *funcs;
} msm_iommu_domains[] = {
	[MSM_IOMMU_DOMAIN_DEFAULT] = {
		.cbname = NULL,
		.funcs = &default_funcs,
	},
	[MSM_IOMMU_DOMAIN_USER] = {
		.cbname = "gfx3d_user",
		.funcs = &user_funcs,
	},
	[MSM_IOMMU_DOMAIN_SECURE] = {
		.cbname = "gfx3d_secure",
		.funcs = &secure_funcs
	},
};

static struct msm_mmu *iommu_create(struct device *dev,
		struct iommu_domain *domain, const struct msm_mmu_funcs *funcs)
{
	struct msm_iommu *iommu;

	iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return ERR_PTR(-ENOMEM);

	iommu->domain = domain;
	msm_mmu_init(&iommu->base, dev, &funcs);
	iommu_set_fault_handler(domain, msm_fault_handler, iommu);

	return &iommu->base;
}

struct msm_mmu *msm_iommu_new(struct device *parent,
		enum msm_iommu_domain_type type, struct iommu_domain *domain)
{
	struct device *dev = parent;

	if (type >= ARRAY_SIZE(msm_iommu_domains) ||
		!msm_iommu_domains[type].funcs)
		return ERR_PTR(-ENODEV);

	if (msm_iommu_domains[type].cbname) {
		dev = find_context_bank(msm_iommu_domains[type].cbname);
		if (IS_ERR(dev))
			return ERR_CAST(dev);
	}

	return iommu_create(dev, domain, msm_iommu_domains[type].funcs);
}

/*
 * Given a base domain that is attached to a IOMMU device try to create a
 * dynamic domain that is also attached to the same device but allocates a new
 * pagetable. This is used to allow multiple pagetables to be attached to the
 * same device.
 */
struct msm_mmu *msm_iommu_new_dynamic(struct msm_mmu *base)
{
	struct msm_iommu *base_iommu = to_msm_iommu(base);
	struct iommu_domain *domain;
	struct msm_mmu *mmu;
	int ret, val = 1;
	struct msm_iommu *child_iommu;

	/* Don't continue if the base domain didn't have the support we need */
	if (!base || base_iommu->allow_dynamic == false)
		return ERR_PTR(-EOPNOTSUPP);

	domain = iommu_domain_alloc(&platform_bus_type);
	if (!domain)
		return ERR_PTR(-ENODEV);

	mmu = iommu_create(base->dev, domain, &dynamic_funcs);

	if (IS_ERR(mmu)) {
		if (domain)
			iommu_domain_free(domain);
		return mmu;
	}

	ret = iommu_domain_set_attr(domain, DOMAIN_ATTR_DYNAMIC, &val);
	if (ret) {
		msm_iommu_destroy(mmu);
		return ERR_PTR(ret);
	}

	/* Set the context bank to match the base domain */
	iommu_domain_set_attr(domain, DOMAIN_ATTR_CONTEXT_BANK,
		&base_iommu->cb);

	/* Mark the dynamic domain as I/O coherent if the base domain is */
	child_iommu = to_msm_iommu(mmu);
	child_iommu->is_coherent = base_iommu->is_coherent;

	return mmu;
}
